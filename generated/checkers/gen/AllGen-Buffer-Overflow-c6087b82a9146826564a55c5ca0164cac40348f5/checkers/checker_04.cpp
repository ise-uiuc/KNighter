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
#include "clang/AST/Expr.h"
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"
#include <cstdint>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(SizeBoundMap, const MemRegion*, uint64_t)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrToArraySizeMap, const MemRegion*, uint64_t)

namespace {

class SAGenTestChecker : public Checker<
  check::PreCall,
  check::PostStmt<DeclStmt>,
  check::Bind
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "copy_from_user length not capped by destination size", "Memory Safety")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      static bool isIntegerLike(QualType QT);
      static bool isPointerLike(QualType QT);
      static bool containsMinusOne(const Expr *E, CheckerContext &C);
      static const DeclRefExpr* findArrayDeclRef(const Expr *E);
      static bool getArraySizeFromAny(const Expr *E, CheckerContext &C, uint64_t &OutSize, std::string &OutName);
      static const MemRegion* getVarRegionForDecl(const VarDecl *VD, CheckerContext &C);

      static bool computeBoundFromExpr(const Expr *E, CheckerContext &C, uint64_t &Bound);
      static void tryRecordPtrToArrayAlias(ProgramStateRef &State, const MemRegion *LHSReg,
                                           const Expr *RHS, CheckerContext &C);
      static void tryRecordIntegerBound(ProgramStateRef &State, const MemRegion *LHSReg,
                                        const Expr *RHS, CheckerContext &C);

      void reportUnboundedCopy(const CallEvent &Call, CheckerContext &C) const;
};

// ---------- Helper Implementations ----------

bool SAGenTestChecker::isIntegerLike(QualType QT) {
  return QT->isIntegerType();
}

bool SAGenTestChecker::isPointerLike(QualType QT) {
  return QT->isPointerType();
}

bool SAGenTestChecker::containsMinusOne(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "- 1", C) || ExprHasName(E, "-1", C);
}

const DeclRefExpr* SAGenTestChecker::findArrayDeclRef(const Expr *E) {
  if (!E) return nullptr;
  return findSpecificTypeInChildren<DeclRefExpr>(E);
}

bool SAGenTestChecker::getArraySizeFromAny(const Expr *E, CheckerContext &C,
                                           uint64_t &OutSize, std::string &OutName) {
  if (!E) return false;

  // Case 1: direct DeclRefExpr to an array (possibly after ignoring imp casts)
  llvm::APInt Size;
  const Expr *EI = E->IgnoreImpCasts();
  if (getArraySizeFromExpr(Size, EI)) {
    OutSize = Size.getZExtValue();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(EI)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        OutName = VD->getName().str();
      }
    }
    return true;
  }

  // Case 2: find DeclRefExpr within complex expr, e.g., &arr[0]
  if (const DeclRefExpr *DRE = findArrayDeclRef(E)) {
    llvm::APInt Size2;
    if (getArraySizeFromExpr(Size2, DRE)) {
      OutSize = Size2.getZExtValue();
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        OutName = VD->getName().str();
      }
      return true;
    }
  }

  // Case 3: RHS is a pointer variable that aliases an array recorded in state.
  // Use getMemRegionFromExpr; do not ignore implicit before calling it.
  if (const MemRegion *MR = getMemRegionFromExpr(E, C)) {
    MR = MR->getBaseRegion();
    ProgramStateRef State = C.getState();
    if (const uint64_t *KnownSize = State->get<PtrToArraySizeMap>(MR)) {
      OutSize = *KnownSize;
      // Try to infer the array name (not strictly required).
      if (const auto *VR = dyn_cast<VarRegion>(MR)) {
        OutName = VR->getDecl()->getName().str();
      }
      return true;
    }
  }

  return false;
}

const MemRegion* SAGenTestChecker::getVarRegionForDecl(const VarDecl *VD, CheckerContext &C) {
  if (!VD) return nullptr;
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx) return nullptr;
  MemRegionManager &MRM = C.getSValBuilder().getRegionManager();
  const MemRegion *MR = MRM.getVarRegion(VD, LCtx);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

// Attempt to compute a maximum bound from an expression that contains sizeof(array) or min(..., sizeof(array)[-1]).
bool SAGenTestChecker::computeBoundFromExpr(const Expr *E, CheckerContext &C, uint64_t &Bound) {
  if (!E) return false;

  // Heuristic using source text: min( and sizeof(
  if (ExprHasName(E, "sizeof(", C)) {
    uint64_t A = 0;
    std::string ArrName;
    if (getArraySizeFromAny(E, C, A, ArrName)) {
      if (containsMinusOne(E, C)) {
        if (A == 0) return false; // avoid underflow
        Bound = A - 1;
        return true;
      }
      Bound = A;
      return true;
    }
  }

  // If not matched, fail.
  return false;
}

void SAGenTestChecker::tryRecordPtrToArrayAlias(ProgramStateRef &State, const MemRegion *LHSReg,
                                                const Expr *RHS, CheckerContext &C) {
  if (!LHSReg || !RHS) return;
  uint64_t A = 0;
  std::string ArrName;
  if (getArraySizeFromAny(RHS, C, A, ArrName)) {
    State = State->set<PtrToArraySizeMap>(LHSReg, A);
    return;
  }
  // If RHS is another pointer with known alias size, propagate.
  if (const MemRegion *RHSReg = getMemRegionFromExpr(RHS, C)) {
    RHSReg = RHSReg->getBaseRegion();
    if (const uint64_t *Known = State->get<PtrToArraySizeMap>(RHSReg)) {
      State = State->set<PtrToArraySizeMap>(LHSReg, *Known);
    }
  }
}

void SAGenTestChecker::tryRecordIntegerBound(ProgramStateRef &State, const MemRegion *LHSReg,
                                             const Expr *RHS, CheckerContext &C) {
  if (!LHSReg || !RHS) return;

  // Case 1: RHS contains sizeof or min with sizeof
  uint64_t Bound = 0;
  if (computeBoundFromExpr(RHS, C, Bound)) {
    State = State->set<SizeBoundMap>(LHSReg, Bound);
    return;
  }

  // Case 2: RHS is another variable with known bound
  if (const MemRegion *RHSReg = getMemRegionFromExpr(RHS, C)) {
    RHSReg = RHSReg->getBaseRegion();
    if (const uint64_t *KnownB = State->get<SizeBoundMap>(RHSReg)) {
      State = State->set<SizeBoundMap>(LHSReg, *KnownB);
    }
  }
}

// ---------- Core Checkers ----------

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Use source-text based matcher per suggestions
  if (!ExprHasName(Origin, "copy_from_user", C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DestExpr = Call.getArgExpr(0);
  const Expr *LenExpr  = Call.getArgExpr(2);
  if (!DestExpr || !LenExpr)
    return;

  // Determine destination array size A
  uint64_t A = 0;
  std::string DestName;
  if (!getArraySizeFromAny(DestExpr, C, A, DestName)) {
    // Unknown destination size: avoid false positives
    return;
  }

  // Try to prove the length is safe
  bool Safe = false;

  // Case 1: LenExpr is constant
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, LenExpr, C)) {
    uint64_t V = EvalRes.getZExtValue();
    if (V <= A) {
      Safe = true;
    }
  }

  // Case 2: LenExpr contains sizeof(dest)
  if (!Safe && !DestName.empty()) {
    if (ExprHasName(LenExpr, "sizeof(", C) && ExprHasName(LenExpr, DestName, C)) {
      // Heuristic: if it has sizeof(dest) we consider it bounded
      Safe = true;
    }
  }

  // Case 3: LenExpr is an identifier with known bound
  if (!Safe) {
    const Expr *LenEI = LenExpr;
    if (const DeclRefExpr *LenDRE = dyn_cast_or_null<DeclRefExpr>(LenEI->IgnoreImplicit())) {
      // Use getMemRegionFromExpr without stripping implicit as per suggestion
      if (const MemRegion *LenReg = getMemRegionFromExpr(LenExpr, C)) {
        LenReg = LenReg->getBaseRegion();
        ProgramStateRef State = C.getState();
        if (const uint64_t *Bound = State->get<SizeBoundMap>(LenReg)) {
          if (*Bound <= A)
            Safe = true;
        }
      }
    }
  }

  // Case 4: Use constraint manager inferred max
  if (!Safe) {
    SVal LenVal = C.getState()->getSVal(LenExpr, C.getLocationContext());
    if (SymbolRef Sym = LenVal.getAsSymbol()) {
      if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
        uint64_t MV = MaxV->getZExtValue();
        if (MV <= A)
          Safe = true;
      }
    }
  }

  if (!Safe) {
    reportUnboundedCopy(Call, C);
  }
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx) return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    const MemRegion *VarReg = getVarRegionForDecl(VD, C);
    if (!VarReg) continue;

    // Integer-like variables: record bounds
    if (isIntegerLike(VD->getType())) {
      uint64_t Bound = 0;
      if (computeBoundFromExpr(Init, C, Bound)) {
        State = State->set<SizeBoundMap>(VarReg, Bound);
      } else {
        // If initializer is a reference to another bounded integer, propagate.
        if (const MemRegion *InitReg = getMemRegionFromExpr(Init, C)) {
          InitReg = InitReg->getBaseRegion();
          if (const uint64_t *Known = State->get<SizeBoundMap>(InitReg)) {
            State = State->set<SizeBoundMap>(VarReg, *Known);
          }
        }
      }
    }

    // Pointer-like variables: record pointer-to-array alias if initializer refers to array
    if (isPointerLike(VD->getType())) {
      uint64_t A = 0;
      std::string ArrName;
      if (getArraySizeFromAny(Init, C, A, ArrName)) {
        State = State->set<PtrToArraySizeMap>(VarReg, A);
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }

  // We prefer to only process clear assignment statements
  const auto *BO = dyn_cast_or_null<BinaryOperator>(StoreE);
  if (!BO || !BO->isAssignmentOp()) {
    C.addTransition(State);
    return;
  }

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS) {
    C.addTransition(State);
    return;
  }

  QualType LHSTy = LHS->getType();

  if (isIntegerLike(LHSTy)) {
    tryRecordIntegerBound(State, LHSReg, RHS, C);
  } else if (isPointerLike(LHSTy)) {
    tryRecordPtrToArrayAlias(State, LHSReg, RHS, C);
  }

  C.addTransition(State);
}

// ---------- Reporting ----------

void SAGenTestChecker::reportUnboundedCopy(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_from_user length not capped by destination size", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded copy_from_user into fixed-size stack buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
