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
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables bound to the result of roundup_pow_of_two(arg).
REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion *, const Expr *)

namespace {

class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe overflow check after roundup_pow_of_two", "API Misuse")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      static bool is32BitULong(CheckerContext &C);
      static const Expr *extractZeroTestedExpr(const Expr *CondE, CheckerContext &C);
      static bool isRoundupPow2Call(const CallExpr *CE, CheckerContext &C);
};

bool SAGenTestChecker::is32BitULong(CheckerContext &C) {
  const ASTContext &ACtx = C.getASTContext();
  return ACtx.getTypeSize(ACtx.UnsignedLongTy) == 32;
}

bool SAGenTestChecker::isRoundupPow2Call(const CallExpr *CE, CheckerContext &C) {
  if (!CE) return false;
  const Expr *Callee = CE->getCallee();
  if (!Callee) return false;
  // Use source text-based match as suggested.
  return ExprHasName(Callee, "roundup_pow_of_two", C);
}

const Expr *SAGenTestChecker::extractZeroTestedExpr(const Expr *CondE, CheckerContext &C) {
  if (!CondE) return nullptr;
  const ASTContext &ACtx = C.getASTContext();
  const Expr *E = CondE->IgnoreParenImpCasts();

  if (const auto *U = dyn_cast<UnaryOperator>(E)) {
    if (U->getOpcode() == UO_LNot) {
      return U->getSubExpr()->IgnoreParenImpCasts();
    }
  }

  if (const auto *B = dyn_cast<BinaryOperator>(E)) {
    if (B->getOpcode() == BO_EQ) {
      const Expr *L = B->getLHS()->IgnoreParenImpCasts();
      const Expr *R = B->getRHS()->IgnoreParenImpCasts();

      llvm::APSInt Val;
      if (EvaluateExprToInt(Val, R, C)) {
        if (Val == 0)
          return L;
      }
      if (EvaluateExprToInt(Val, L, C)) {
        if (Val == 0)
          return R;
      }
    }
  }

  return nullptr;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;
  R = R->getBaseRegion();
  if (!R)
    return;

  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE) {
    // Not binding from a call expression; clear any prior tracking.
    State = State->remove<RoundupResMap>(R);
    C.addTransition(State);
    return;
  }

  if (isRoundupPow2Call(CE, C)) {
    if (CE->getNumArgs() >= 1) {
      const Expr *ArgE = CE->getArg(0);
      if (ArgE) {
        State = State->set<RoundupResMap>(R, ArgE->IgnoreImpCasts());
        C.addTransition(State);
        return;
      }
    }
  }

  // Some other call; clear tracking for this region.
  State = State->remove<RoundupResMap>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!is32BitULong(C))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const Expr *X = extractZeroTestedExpr(CondE, C);
  if (!X)
    return;

  // Case 1: Direct call in condition.
  if (const auto *CE = dyn_cast<CallExpr>(X->IgnoreParenImpCasts())) {
    if (isRoundupPow2Call(CE, C)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "roundup_pow_of_two() overflow cannot be detected via == 0 on 32-bit; pre-check the input before rounding",
          N);
      R->addRange(Condition->getSourceRange());
      C.emitReport(std::move(R));
      return;
    }
  }

  // Case 2: Variable that was assigned from roundup_pow_of_two().
  const MemRegion *MR = getMemRegionFromExpr(X, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const Expr *const *TrackedArg = State->get<RoundupResMap>(MR);
  if (!TrackedArg)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "roundup_pow_of_two() overflow cannot be detected via == 0 on 32-bit; pre-check the input before rounding",
      N);
  Rpt->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Rpt));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Warns when code checks roundup_pow_of_two(x) == 0 on 32-bit; pre-check x before rounding",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
