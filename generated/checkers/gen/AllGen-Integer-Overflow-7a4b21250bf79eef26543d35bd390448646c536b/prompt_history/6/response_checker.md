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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track symbols that are results of roundup_pow_of_two()
REGISTER_SET_WITH_PROGRAMSTATE(RoundupSyms, SymbolRef)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "API Misuse", "Integer Overflow/UB")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      bool isRoundupPow2CallExpr(const Expr *E, CheckerContext &C) const;
      bool isZero(const Expr *E, CheckerContext &C) const;
      void reportUnsafeZeroCheck(const Stmt *S, CheckerContext &C) const;
};

bool SAGenTestChecker::isRoundupPow2CallExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  // Look downwards for a CallExpr and check its callee name.
  if (const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(E)) {
    return ExprHasName(CE, "roundup_pow_of_two", C);
  }
  return false;
}

bool SAGenTestChecker::isZero(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  llvm::APSInt V;
  if (EvaluateExprToInt(V, E, C)) {
    return V == 0;
  }
  return false;
}

void SAGenTestChecker::reportUnsafeZeroCheck(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Do not zero-check roundup_pow_of_two() result; overflow is UB on 32-bit. Pre-check arg (> 1UL << 31) before calling.",
      N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Identify roundup_pow_of_two() using the source text of the origin expr.
  if (!ExprHasName(OriginExpr, "roundup_pow_of_two", C))
    return;

  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<RoundupSyms>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  CondE = CondE->IgnoreParenImpCasts();

  auto CheckExprForRoundupResult = [&](const Expr *E) -> bool {
    if (!E) return false;
    // Check if the expression evaluates to a tracked roundup_pow_of_two symbol
    SVal SV = State->getSVal(E, C.getLocationContext());
    if (SymbolRef Sym = SV.getAsSymbol()) {
      if (State->contains<RoundupSyms>(Sym))
        return true;
    }
    // Or if the expression directly calls roundup_pow_of_two()
    if (isRoundupPow2CallExpr(E, C))
      return true;

    return false;
  };

  bool ShouldReport = false;

  // Pattern 1: if (!X)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *X = UO->getSubExpr()->IgnoreParenImpCasts();
      if (CheckExprForRoundupResult(X))
        ShouldReport = true;
    }
  }
  // Pattern 2: if (X == 0) or if (0 == X)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      bool LIsZero = isZero(L, C);
      bool RIsZero = isZero(R, C);

      if (LIsZero && !RIsZero) {
        if (CheckExprForRoundupResult(R))
          ShouldReport = true;
      } else if (RIsZero && !LIsZero) {
        if (CheckExprForRoundupResult(L))
          ShouldReport = true;
      }
    }
  }

  if (ShouldReport) {
    reportUnsafeZeroCheck(Condition, C);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects zero-check of roundup_pow_of_two() results (UB on 32-bit); suggest pre-validating input",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
