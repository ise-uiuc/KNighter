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
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map: pointer MemRegion -> destination fixed-size array VarDecl
REGISTER_MAP_WITH_PROGRAMSTATE(BufAliasMap, const MemRegion *, const VarDecl *)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "copy_from_user into fixed-size buffer",
                       "Memory Error")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  bool isCopyFromUser(const CallEvent &Call, CheckerContext &C) const;
  bool getArrayFromDestExpr(const Expr *Dest, const VarDecl *&ArrVD,
                            llvm::APInt &ArrSize,
                            CheckerContext &C) const;
  bool lenExprLooksUnboundedUserCount(const Expr *LenE, const VarDecl *ArrVD,
                                      CheckerContext &C) const;
  void reportUnbounded(const CallEvent &Call, const Expr *DestE,
                       CheckerContext &C, StringRef Msg) const;
};

bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call,
                                      CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Use source-based name matching for robustness as suggested.
  if (ExprHasName(Origin, "copy_from_user", C))
    return true;
  if (ExprHasName(Origin, "__copy_from_user", C))
    return true;
  return false;
}

bool SAGenTestChecker::getArrayFromDestExpr(const Expr *Dest,
                                            const VarDecl *&ArrVD,
                                            llvm::APInt &ArrSize,
                                            CheckerContext &C) const {
  ArrVD = nullptr;

  // Try direct array use: e.g., copy_from_user(mybuf, ...)
  if (const auto *DRE =
          dyn_cast<DeclRefExpr>(Dest->IgnoreParenImpCasts())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (const auto *CAT =
              dyn_cast<ConstantArrayType>(VD->getType().getTypePtr())) {
        ArrVD = VD;
        ArrSize = CAT->getSize();
        return true;
      }
    }
  }

  // Try alias via program state map: e.g., pbuf = mybuf; copy_from_user(pbuf, ...)
  const MemRegion *MR = getMemRegionFromExpr(Dest, C);
  if (!MR)
    return false;
  MR = MR->getBaseRegion();
  if (!MR)
    return false;

  ProgramStateRef State = C.getState();
  const VarDecl *const *VDPtr = State->get<BufAliasMap>(MR);
  if (!VDPtr)
    return false;

  const VarDecl *VD = *VDPtr;
  if (!VD)
    return false;

  if (const auto *CAT =
          dyn_cast<ConstantArrayType>(VD->getType().getTypePtr())) {
    ArrVD = VD;
    ArrSize = CAT->getSize();
    return true;
  }

  return false;
}

bool SAGenTestChecker::lenExprLooksUnboundedUserCount(const Expr *LenE,
                                                      const VarDecl *ArrVD,
                                                      CheckerContext &C) const {
  if (!LenE)
    return false;

  // Suppress if there is a clear clamp via min(...)
  if (ExprHasName(LenE, "min", C))
    return false;

  // Suppress if expression mentions sizeof(array)
  if (ArrVD) {
    if (ExprHasName(LenE, "sizeof", C) &&
        ExprHasName(LenE, ArrVD->getName(), C))
      return false;
  }

  // Direct parameter reference named "nbytes" or "count"
  if (const auto *DRE =
          dyn_cast<DeclRefExpr>(LenE->IgnoreParenImpCasts())) {
    if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
      StringRef N = PVD->getName();
      if (N.equals("nbytes") || N.equals("count"))
        return true;
    }
  }

  // Heuristic text search for common names
  if (ExprHasName(LenE, "nbytes", C) || ExprHasName(LenE, "count", C))
    return true;

  return false;
}

void SAGenTestChecker::reportUnbounded(const CallEvent &Call, const Expr *DestE,
                                       CheckerContext &C, StringRef Msg) const {
  ExplodedNode *EN = C.generateNonFatalErrorNode();
  if (!EN)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, EN);
  R->addRange(Call.getSourceRange());
  if (DestE)
    R->addRange(DestE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCopyFromUser(Call, C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DestE = Call.getArgExpr(0);
  const Expr *LenE = Call.getArgExpr(2);
  if (!DestE || !LenE)
    return;

  // Resolve destination array
  const VarDecl *ArrVD = nullptr;
  llvm::APInt ArrSize; // number of bytes in array
  if (!getArrayFromDestExpr(DestE, ArrVD, ArrSize, C))
    return; // only flag when we know it's a fixed-size local array

  // If length is a constant, check it against the array size.
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, LenE, C)) {
    // Negative or zero-length copies are not overflows.
    if (EvalRes.isSigned() && EvalRes.isNegative())
      return;

    llvm::APSInt ArrSizeAPS(EvalRes.getBitWidth(), /*isUnsigned=*/true);
    ArrSizeAPS = ArrSize.getLimitedValue();

    llvm::APSInt LenVal = EvalRes;
    if (LenVal.isSigned())
      LenVal.setIsUnsigned(true); // compare as unsigned

    if (LenVal > ArrSizeAPS) {
      reportUnbounded(Call, DestE, C,
                      "copy_from_user length exceeds destination buffer");
    }
    return; // handled the constant case
  }

  // Heuristic: unbounded user length used directly without clamping
  if (lenExprLooksUnboundedUserCount(LenE, ArrVD, C)) {
    reportUnbounded(Call, DestE, C,
                    "copy_from_user into fixed-size buffer uses unbounded user length");
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;

  // We care about aliases to arrays: find if RHS base region is a VarDecl of a fixed array.
  if (const auto *VR = dyn_cast<VarRegion>(RHSReg)) {
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      return;

    // Only care about fixed-size arrays
    if (dyn_cast<ConstantArrayType>(VD->getType().getTypePtr())) {
      // Track alias: pointer (LHSReg) -> array VarDecl (VD)
      State = State->set<BufAliasMap>(LHSReg, VD);
      C.addTransition(State);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect unbounded copy_from_user into fixed-size local buffers", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
