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
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map variables that currently hold the result of roundup_pow_of_two(...)
// We keep the originating Stmt* (CallExpr) just for diagnostic purposes.
REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion*, const Stmt*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::BranchCondition
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker()
          : BT(new BugType(this, "Unreliable overflow check after roundup_pow_of_two()",
                                 "Logic error")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      static bool isRoundupPow2Call(const CallExpr *CE, CheckerContext &C);
      static bool isZeroConstant(const Expr *E, CheckerContext &C);
      static bool extractCheckedExpr(const Expr *Cond, const Expr* &ECheck, CheckerContext &C);
      void reportIssue(const Stmt *CondSite, const Stmt *OriginCE, CheckerContext &C) const;
};

// Helper: check if a CallExpr calls roundup_pow_of_two(...)
bool SAGenTestChecker::isRoundupPow2Call(const CallExpr *CE, CheckerContext &C) {
  if (!CE)
    return false;

  // Prefer robust name check on source text
  if (ExprHasName(CE, "roundup_pow_of_two", C))
    return true;

  // Fall back to direct callee if available
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (FD->getIdentifier() && FD->getName() == "roundup_pow_of_two")
      return true;
  }
  // Also try on the callee expr directly
  if (ExprHasName(CE->getCallee(), "roundup_pow_of_two", C))
    return true;

  return false;
}

// Helper: determine if expression equals integer zero (or null constant)
bool SAGenTestChecker::isZeroConstant(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C))
    return Res == 0;

  if (const auto *IL = dyn_cast<IntegerLiteral>(E->IgnoreParenCasts()))
    return IL->getValue() == 0;

  // Also consider NULL-like constants
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

  return false;
}

// Helper: from a condition, extract the expression that is being checked for zero
// Match: !X  -> ECheck = X
//        X == 0 or 0 == X -> ECheck = X
bool SAGenTestChecker::extractCheckedExpr(const Expr *Cond, const Expr* &ECheck, CheckerContext &C) {
  if (!Cond)
    return false;

  const Expr *ECond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(ECond)) {
    if (UO->getOpcode() == UO_LNot) {
      ECheck = UO->getSubExpr();
      return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(ECond)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS();
      const Expr *R = BO->getRHS();
      if (isZeroConstant(L, C)) {
        ECheck = R;
        return true;
      }
      if (isZeroConstant(R, C)) {
        ECheck = L;
        return true;
      }
    }
  }

  return false;
}

// Report a concise warning
void SAGenTestChecker::reportIssue(const Stmt *CondSite, const Stmt *OriginCE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unreliable overflow check after roundup_pow_of_two()",
      N);

  if (CondSite)
    R->addRange(CondSite->getSourceRange());

  if (OriginCE) {
    PathDiagnosticLocation Loc =
        PathDiagnosticLocation::createBegin(OriginCE, C.getSourceManager(), C.getLocationContext());
    R->addNote("Value comes from roundup_pow_of_two() here", Loc, &C.getSourceManager());
  }

  R->addNote("roundup_pow_of_two() may overflow (UB) on 32-bit; check the input before rounding (e.g., x > 1UL << 31).");

  C.emitReport(std::move(R));
}

// Track binds: mark variables assigned from roundup_pow_of_two(...); clear otherwise
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *LReg = Loc.getAsRegion();
  if (!LReg)
    return;
  LReg = LReg->getBaseRegion();
  if (!LReg)
    return;

  ProgramStateRef State = C.getState();

  // Find a CallExpr within this bind stmt (works for init and assignment)
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE) {
    // No call involved -> clear stale info for this variable
    State = State->remove<RoundupResMap>(LReg);
    C.addTransition(State);
    return;
  }

  // Only track if this call is roundup_pow_of_two(...)
  if (isRoundupPow2Call(CE, C)) {
    State = State->set<RoundupResMap>(LReg, CE);
  } else {
    State = State->remove<RoundupResMap>(LReg);
  }

  C.addTransition(State);
}

// Detect conditions like !n or n == 0 where n is the result of roundup_pow_of_two(...)
// Also detect !roundup_pow_of_two(x) and roundup_pow_of_two(x) == 0
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Only warn on 32-bit unsigned long targets
  ASTContext &ACtx = C.getASTContext();
  if (ACtx.getTypeSize(ACtx.UnsignedLongTy) != 32)
    return;

  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  const Expr *CheckedExpr = nullptr;
  if (!extractCheckedExpr(CondE, CheckedExpr, C))
    return;

  // Case 1: Direct call in the check (e.g., if (!roundup_pow_of_two(x)))
  if (const auto *CE = dyn_cast<CallExpr>(CheckedExpr->IgnoreParenImpCasts())) {
    if (isRoundupPow2Call(CE, C)) {
      reportIssue(Condition, CE, C);
      return;
    }
  }

  // Case 2: Variable previously assigned from roundup_pow_of_two(...)
  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(CheckedExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  if (const Stmt *Origin = State->get<RoundupResMap>(MR)) {
    reportIssue(Condition, Origin, C);
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect unreliable overflow checks after roundup_pow_of_two() on 32-bit targets",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
