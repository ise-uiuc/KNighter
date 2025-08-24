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

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::BranchCondition,
        check::Location> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Optional resource NULL dereference", "API Misuse")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool isOptionalGetterName(StringRef Name) {
    return Name == "devm_gpiod_get_array_optional" ||
           Name == "gpiod_get_array_optional" ||
           Name == "devm_gpiod_get_optional" ||
           Name == "gpiod_get_optional";
  }

  static bool isOptionalGetterCallExpr(const CallExpr *CE, CheckerContext &C) {
    if (!CE) return false;
    const Expr *CalleeE = CE->getCallee();
    if (!CalleeE) return false;

    // Use source-text match via utility helper for robustness.
    if (ExprHasName(CalleeE, "devm_gpiod_get_array_optional", C)) return true;
    if (ExprHasName(CalleeE, "gpiod_get_array_optional", C)) return true;
    if (ExprHasName(CalleeE, "devm_gpiod_get_optional", C)) return true;
    if (ExprHasName(CalleeE, "gpiod_get_optional", C)) return true;

    return false;
  }

  static const MemRegion* getCanonical(const MemRegion *R, ProgramStateRef State) {
    if (!R) return nullptr;
    R = R->getBaseRegion();
    // Follow aliasing chain to the canonical root.
    while (true) {
      const MemRegion *Next = State->get<PtrAliasMap>(R);
      if (!Next) break;
      const MemRegion *NextBase = Next->getBaseRegion();
      if (NextBase == R) break;
      R = NextBase;
    }
    return R;
  }

  static ProgramStateRef markOptional(ProgramStateRef State, const MemRegion *R) {
    if (!R) return State;
    R = getCanonical(R, State);
    if (!R) return State;
    // false means "unchecked"
    return State->set<OptionalPtrMap>(R, false);
  }

  static ProgramStateRef setNullChecked(ProgramStateRef State, const MemRegion *R) {
    if (!R) return State;
    R = getCanonical(R, State);
    if (!R) return State;
    const bool *Present = State->get<OptionalPtrMap>(R);
    if (Present) {
      State = State->set<OptionalPtrMap>(R, true);
    }
    return State;
  }

  static const MemRegion* getPointerRegionFromExpr(const Expr *E, CheckerContext &C) {
    if (!E) return nullptr;
    const MemRegion *MR = getMemRegionFromExpr(E, C);
    if (!MR) return nullptr;
    MR = MR->getBaseRegion();
    return MR;
  }

  // Extract pointer expr from condition that represents a NULL-check
  static const Expr* extractPointerExprFromCondition(const Stmt *Condition, CheckerContext &C) {
    if (!Condition) return nullptr;
    const Expr *CondE = dyn_cast<Expr>(Condition);
    if (!CondE) return nullptr;

    // Handle IS_ERR_OR_NULL(ptr)
    if (ExprHasName(CondE, "IS_ERR_OR_NULL", C)) {
      if (const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(Condition)) {
        if (CE->getNumArgs() >= 1)
          return CE->getArg(0)->IgnoreParenImpCasts();
      }
      return nullptr;
    }

    // Ignore IS_ERR(...) alone - not a NULL-check
    if (ExprHasName(CondE, "IS_ERR", C) && !ExprHasName(CondE, "IS_ERR_OR_NULL", C))
      return nullptr;

    CondE = CondE->IgnoreParenImpCasts();

    // if (!ptr)
    if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
      if (UO->getOpcode() == UO_LNot) {
        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (Sub->getType()->isPointerType())
          return Sub;
      }
    }

    // if (ptr == NULL) or if (ptr != NULL)
    if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
      if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
        bool LHSNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
        bool RHSNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
        if (LHSNull && !RHSNull && RHS->getType()->isPointerType())
          return RHS;
        if (RHSNull && !LHSNull && LHS->getType()->isPointerType())
          return LHS;
      }
    }

    // if (ptr)
    if (CondE->getType()->isPointerType())
      return CondE;

    return nullptr;
  }

  // Detect dereference and extract the base pointer region
  static bool isDereferenceStmt(const Stmt *S, CheckerContext &C, const MemRegion *&BasePtrRegion) {
    BasePtrRegion = nullptr;
    if (!S) return false;

    // 1) Member access via '->'
    const MemberExpr *ME = dyn_cast<MemberExpr>(S);
    if (!ME) ME = findSpecificTypeInChildren<MemberExpr>(S);
    if (ME && ME->isArrow()) {
      const Expr *BaseE = ME->getBase()->IgnoreParenImpCasts();
      BasePtrRegion = getPointerRegionFromExpr(BaseE, C);
      if (BasePtrRegion) {
        BasePtrRegion = getCanonical(BasePtrRegion, C.getState());
        return true;
      }
    }

    // 2) UnaryOperator '*'
    const UnaryOperator *UO = dyn_cast<UnaryOperator>(S);
    if (!UO) UO = findSpecificTypeInChildren<UnaryOperator>(S);
    if (UO && UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (Sub && Sub->getType()->isPointerType()) {
        BasePtrRegion = getPointerRegionFromExpr(Sub, C);
        if (BasePtrRegion) {
          BasePtrRegion = getCanonical(BasePtrRegion, C.getState());
          return true;
        }
      }
    }

    // 3) ArraySubscriptExpr e[i] where e is a pointer (not array)
    const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S);
    if (!ASE) ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S);
    if (ASE) {
      const Expr *BaseE = ASE->getBase()->IgnoreParenImpCasts();
      if (BaseE && BaseE->getType()->isPointerType()) {
        BasePtrRegion = getPointerRegionFromExpr(BaseE, C);
        if (BasePtrRegion) {
          BasePtrRegion = getCanonical(BasePtrRegion, C.getState());
          return true;
        }
      }
    }

    return false;
  }

  void reportUncheckedDeref(const Stmt *S, CheckerContext &C) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N) return;
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Optional getter may return NULL; missing NULL check before dereference.", N);
    if (S)
      R->addRange(S->getSourceRange());
    C.emitReport(std::move(R));
  }
};

// Record aliasing and seed optional-pointer tracking
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (LHSReg) LHSReg = LHSReg->getBaseRegion();

  const MemRegion *RHSReg = Val.getAsRegion();
  if (RHSReg) RHSReg = RHSReg->getBaseRegion();

  // Track alias: LHS -> RHS and RHS -> LHS
  if (LHSReg && RHSReg) {
    const MemRegion *CanonLHS = getCanonical(LHSReg, State);
    const MemRegion *CanonRHS = getCanonical(RHSReg, State);
    if (CanonLHS && CanonRHS && CanonLHS != CanonRHS) {
      State = State->set<PtrAliasMap>(CanonLHS, CanonRHS);
      State = State->set<PtrAliasMap>(CanonRHS, CanonLHS);

      // Propagate optional-checked state if RHS is known optional
      if (const bool *Checked = State->get<OptionalPtrMap>(CanonRHS)) {
        State = State->set<OptionalPtrMap>(CanonLHS, *Checked);
      }
    }
  }

  // If this bind originates from an optional getter call, mark LHS as optional (unchecked).
  if (S) {
    const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
    if (CE && isOptionalGetterCallExpr(CE, C) && LHSReg) {
      State = markOptional(State, LHSReg);
    }
  }

  C.addTransition(State);
}

// Observe NULL checks in branch conditions.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *PtrE = extractPointerExprFromCondition(Condition, C);
  if (PtrE) {
    const MemRegion *MR = getPointerRegionFromExpr(PtrE, C);
    if (MR) {
      State = setNullChecked(State, MR);
      C.addTransition(State);
      return;
    }
  }
  C.addTransition(State);
}

// Detect dereferences of unchecked optional pointers.
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad || !S) return;

  const MemRegion *BasePtrRegion = nullptr;
  if (!isDereferenceStmt(S, C, BasePtrRegion))
    return;

  ProgramStateRef State = C.getState();
  if (!BasePtrRegion) return;

  // Check if this base pointer originates from an optional getter and is unchecked.
  const MemRegion *Canon = getCanonical(BasePtrRegion, State);
  if (!Canon) return;

  const bool *Checked = State->get<OptionalPtrMap>(Canon);
  if (Checked && *Checked == false) {
    reportUncheckedDeref(S, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL checks after optional resource getters before dereference",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
