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
#include "clang/AST/ExprCXX.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map: track variables that currently hold the result of roundup_pow_of_two(arg0).
// Key: base MemRegion of the LHS variable. Value: pointer to the 0th argument Expr.
REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion*, const Expr*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Unreliable overflow check after roundup_pow_of_two",
                       "Correctness")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  static bool isZeroInteger(const Expr *E, CheckerContext &C);
  void report(const Stmt *S, CheckerContext &C) const;
  static const MemRegion *getBaseReg(const MemRegion *MR) {
    return MR ? MR->getBaseRegion() : nullptr;
  }
};

// Check if expression evaluates to the integer constant 0.
bool SAGenTestChecker::isZeroInteger(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, E, C))
    return false;
  return Res == 0;
}

void SAGenTestChecker::report(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "roundup_pow_of_two() overflow check via zero is unreliable (UB on 32-bit); pre-validate the input before calling",
      N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// Track assignments from roundup_pow_of_two(...) to a variable, and clear mapping on other assignments.
void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = getBaseReg(LHSReg);
  if (!LHSReg)
    return;

  ProgramStateRef State = C.getState();

  // Try to find a call expression in this store statement.
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (CE && ExprHasName(CE, "roundup_pow_of_two", C)) {
    // Record that LHSReg holds the result of roundup_pow_of_two with this argument.
    if (CE->getNumArgs() >= 1) {
      const Expr *Arg0 = CE->getArg(0);
      State = State->set<RoundupResMap>(LHSReg, Arg0);
      C.addTransition(State);
      return;
    }
  }

  // Otherwise, this assignment overrides previous mapping; remove if present.
  if (State->contains<RoundupResMap>(LHSReg)) {
    State = State->remove<RoundupResMap>(LHSReg);
    C.addTransition(State);
  }
}

// Detect branch conditions that test the result of roundup_pow_of_two() for zero:
// 1) Directly: if (!roundup_pow_of_two(x)) or if (roundup_pow_of_two(x) == 0)
// 2) Indirectly via a variable previously assigned from roundup_pow_of_two: if (!var) or if (var == 0)
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  CondE = CondE->IgnoreParenImpCasts();

  // Case 1a: if (!roundup_pow_of_two(...))
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      // Direct-in-condition roundup_pow_of_two(...)
      if (const CallExpr *CallIn = findSpecificTypeInChildren<CallExpr>(Sub)) {
        if (ExprHasName(CallIn, "roundup_pow_of_two", C)) {
          report(Condition, C);
          return;
        }
      }
      // Variable-based: if (!var)
      const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Sub);
      if (DRE) {
        const MemRegion *MR = getMemRegionFromExpr(DRE, C);
        MR = getBaseReg(MR);
        if (MR) {
          const Expr *const *ArgPtr = State->get<RoundupResMap>(MR);
          if (ArgPtr) {
            report(Condition, C);
            return;
          }
        }
      }
    }
  }

  // Case 1b and 2b: Binary compare with zero: if (roundup_pow_of_two(...) == 0) or if (var == 0) or if (0 == var)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      // Direct call on either side compared to 0
      const CallExpr *CallLHS = dyn_cast<CallExpr>(LHS);
      const CallExpr *CallRHS = dyn_cast<CallExpr>(RHS);

      if (CallLHS && ExprHasName(CallLHS, "roundup_pow_of_two", C) && isZeroInteger(RHS, C)) {
        report(Condition, C);
        return;
      }
      if (CallRHS && ExprHasName(CallRHS, "roundup_pow_of_two", C) && isZeroInteger(LHS, C)) {
        report(Condition, C);
        return;
      }

      // Variable-based: var == 0 or 0 == var, where var is previously recorded.
      auto CheckVarZero = [&](const Expr *VarExpr, const Expr *OtherExpr) -> bool {
        const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(VarExpr);
        if (!DRE)
          return false;
        const MemRegion *MR = getMemRegionFromExpr(DRE, C);
        MR = getBaseReg(MR);
        if (!MR)
          return false;
        if (!State->contains<RoundupResMap>(MR))
          return false;
        return isZeroInteger(OtherExpr, C);
      };

      if (CheckVarZero(LHS, RHS) || CheckVarZero(RHS, LHS)) {
        report(Condition, C);
        return;
      }
    }
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unreliable zero-check overflow pattern after roundup_pow_of_two()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
