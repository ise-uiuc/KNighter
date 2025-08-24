```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state customizations
REGISTER_MAP_WITH_PROGRAMSTATE(PtrToArrayMap, const MemRegion*, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(BoundedLenMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "copy_from_user length not capped", "Buffer Overflow")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isCharType(QualType T);
      static bool isCharArray(const VarDecl *VD);
      static bool getArraySizeFromVarDecl(const VarDecl *VD, llvm::APInt &Size);
      bool getArrayInfoFromExpr(const Expr *E, CheckerContext &C,
                                const VarDecl *&ArrayVD,
                                const MemRegion *&ArrayReg,
                                llvm::APInt &ArraySize) const;
      bool lenExprUsesSizeofArray(const Expr *LenE, const VarDecl *ArrayVD) const;
};

static bool isAssignmentStmtForRegion(const DeclStmt *DS, const MemRegion *LHSReg,
                                      const LocationContext *LCtx, const CheckerContext &C) {
  if (!DS || !LHSReg) return false;
  MemRegionManager &MRMgr = C.getState()->getStateManager().getRegionManager();
  for (const Decl *D : DS->decls()) {
    if (const auto *VD = dyn_cast<VarDecl>(D)) {
      const MemRegion *VR = MRMgr.getVarRegion(VD, LCtx);
      if (!VR) continue;
      VR = VR->getBaseRegion();
      if (VR == LHSReg) return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isCharType(QualType T) {
  T = T.getCanonicalType();
  if (const auto *BT = T->getAs<BuiltinType>()) {
    switch (BT->getKind()) {
    case BuiltinType::Char_U:
    case BuiltinType::Char_S:
    case BuiltinType::SChar:
    case BuiltinType::UChar:
      return true;
    default:
      return false;
    }
  }
  return false;
}

bool SAGenTestChecker::isCharArray(const VarDecl *VD) {
  if (!VD) return false;
  QualType QT = VD->getType();
  const auto *ArrTy = dyn_cast<ConstantArrayType>(QT.getTypePtr());
  if (!ArrTy) return false;
  return isCharType(ArrTy->getElementType());
}

bool SAGenTestChecker::getArraySizeFromVarDecl(const VarDecl *VD, llvm::APInt &Size) {
  if (!VD) return false;
  if (const auto *ArrTy = dyn_cast<ConstantArrayType>(VD->getType().getTypePtr())) {
    Size = ArrTy->getSize();
    return true;
  }
  return false;
}

bool SAGenTestChecker::getArrayInfoFromExpr(const Expr *E, CheckerContext &C,
                                            const VarDecl *&ArrayVD,
                                            const MemRegion *&ArrayReg,
                                            llvm::APInt &ArraySize) const {
  ArrayVD = nullptr;
  ArrayReg = nullptr;

  if (!E) return false;

  // Direct array reference in expression
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (isCharArray(VD)) {
        const MemRegion *MR = getMemRegionFromExpr(DRE, C);
        if (!MR) return false;
        MR = MR->getBaseRegion();
        llvm::APInt ASz;
        if (!getArraySizeFromVarDecl(VD, ASz))
          return false;
        ArrayVD = VD;
        ArrayReg = MR;
        ArraySize = ASz;
        return true;
      }
    }
  }

  // Fallback: pointer that aliases an array
  if (const MemRegion *DestMR = getMemRegionFromExpr(E, C)) {
    DestMR = DestMR->getBaseRegion();
    ProgramStateRef State = C.getState();
    if (const MemRegion * const *AliasedArray = State->get<PtrToArrayMap>(DestMR)) {
      const MemRegion *Base = (*AliasedArray)->getBaseRegion();
      if (const auto *VR = dyn_cast<VarRegion>(Base)) {
        const VarDecl *VD = VR->getDecl();
        if (isCharArray(VD)) {
          llvm::APInt ASz;
          if (!getArraySizeFromVarDecl(VD, ASz))
            return false;
          ArrayVD = VD;
          ArrayReg = Base;
          ArraySize = ASz;
          return true;
        }
      }
    }
  }

  return false;
}

bool SAGenTestChecker::lenExprUsesSizeofArray(const Expr *LenE, const VarDecl *ArrayVD) const {
  if (!LenE || !ArrayVD)
    return false;
  const auto *UETT = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(LenE);
  if (!UETT)
    return false;
  if (UETT->getKind() != UETT_SizeOf)
    return false;

  if (!UETT->isArgumentType()) {
    const Expr *ArgE = UETT->getArgumentExpr();
    if (!ArgE) return false;
    if (const auto *ADRE = findSpecificTypeInChildren<DeclRefExpr>(ArgE)) {
      if (const auto *VD = dyn_cast<VarDecl>(ADRE->getDecl())) {
        return VD == ArrayVD;
      }
    }
  }
  // If it's a type argument, we don't try to match (uncommon for this pattern).
  return false;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (LHSReg)
    LHSReg = LHSReg->getBaseRegion();

  const Expr *RHSExpr = nullptr;

  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      RHSExpr = BO->getRHS();
  } else if (const auto *DS = dyn_cast_or_null<DeclStmt>(S)) {
    // Find the initializer that corresponds to this binding's LHS region.
    if (LHSReg && isAssignmentStmtForRegion(DS, LHSReg, C.getLocationContext(), C)) {
      for (const Decl *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (VD->hasInit()) {
            RHSExpr = VD->getInit();
            break;
          }
        }
      }
    }
  }

  if (RHSExpr && LHSReg) {
    // Goal A: Pointer-to-array alias tracking.
    if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(RHSExpr)) {
      if (const auto *ArrVD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (isCharArray(ArrVD)) {
          const MemRegion *ArrReg = getMemRegionFromExpr(DRE, C);
          if (ArrReg) {
            ArrReg = ArrReg->getBaseRegion();
            State = State->set<PtrToArrayMap>(LHSReg, ArrReg);
          }
        }
      }
    }

    // Goal B: Bounded length variable tracking via min(..., sizeof(array)-1).
    if (ExprHasName(RHSExpr, "min", C) || ExprHasName(RHSExpr, "min_t", C)) {
      const auto *UETT = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHSExpr);
      if (UETT && UETT->getKind() == UETT_SizeOf && !UETT->isArgumentType()) {
        const Expr *ArgE = UETT->getArgumentExpr();
        if (const auto *ADRE = findSpecificTypeInChildren<DeclRefExpr>(ArgE)) {
          if (const auto *AVD = dyn_cast<VarDecl>(ADRE->getDecl())) {
            if (isCharArray(AVD)) {
              const MemRegion *ArrayReg = getMemRegionFromExpr(ADRE, C);
              if (ArrayReg) {
                ArrayReg = ArrayReg->getBaseRegion();
                State = State->set<BoundedLenMap>(ArrayReg, LHSReg);
              }
            }
          }
        }
      }
    }
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE || !ExprHasName(OE, "copy_from_user", C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DstE = Call.getArgExpr(0);
  const Expr *LenE = Call.getArgExpr(2);
  if (!DstE || !LenE)
    return;

  const VarDecl *ArrayVD = nullptr;
  const MemRegion *ArrayReg = nullptr;
  llvm::APInt ArraySize(32, 0);

  // Determine if destination is a fixed-size char array or pointer alias to it.
  if (!getArrayInfoFromExpr(DstE, C, ArrayVD, ArrayReg, ArraySize))
    return; // Can't determine a fixed-size destination array.

  // If length is a constant, compare it with array size.
  llvm::APSInt LenVal;
  if (EvaluateExprToInt(LenVal, LenE, C)) {
    uint64_t LenU = LenVal.getLimitedValue();
    uint64_t ArrU = ArraySize.getLimitedValue();
    if (LenU > ArrU) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N) return;
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "copy_from_user length not capped to destination buffer size", N);
      R->addRange(OE->getSourceRange());
      C.emitReport(std::move(R));
    }
    return; // Constant and <= size: considered safe.
  }

  // Check if LenE is a bounded length variable previously mapped for this array.
  ProgramStateRef State = C.getState();
  const MemRegion *LenMR = getMemRegionFromExpr(LenE, C);
  if (LenMR) {
    LenMR = LenMR->getBaseRegion();
    const MemRegion * const *MappedLen = State->get<BoundedLenMap>(ArrayReg);
    if (MappedLen && *MappedLen == LenMR) {
      // Safe: using a bounded length variable for this array.
      return;
    }
  }

  // Check inline sizeof(array) presence in length expression.
  if (lenExprUsesSizeofArray(LenE, ArrayVD)) {
    // Safe: length expression references sizeof(the same array).
    return;
  }

  // Not provably bounded -> report.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_from_user length not capped to destination buffer size", N);
  R->addRange(OE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects copy_from_user with unbounded length for fixed-size buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
