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

#include "clang/AST/Expr.h" // for BinaryOperator, DeclRefExpr, etc.

using namespace clang;
using namespace ento;
using namespace taint;

// No additional program state customization is needed for this checker.

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Off-by-one error")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportOffByOne(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Remove any surrounding parentheses and cast expressions.
  CondE = CondE->IgnoreParenCasts();

  // Check if the condition is a binary operator.
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    // Check if the operator is '>'.
    if (BO->getOpcode() == BO_GT) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      // Verify that the left-hand side is the channel index 'adc_chan'.
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl()->getNameAsString() == "adc_chan") {
          // Use the utility function to see if the right-hand side text contains "PALMAS_ADC_CH_MAX".
          if (ExprHasName(RHS, "PALMAS_ADC_CH_MAX", C)) {
            // The condition "adc_chan > PALMAS_ADC_CH_MAX" is an off-by-one error.
            reportOffByOne(Condition, C);
          }
        }
      }
    }
  }
}

void SAGenTestChecker::reportOffByOne(const Stmt *Condition, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Off-by-one error: channel index check should use '>=' instead of '>'", N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects off-by-one errors in channel index validation", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```