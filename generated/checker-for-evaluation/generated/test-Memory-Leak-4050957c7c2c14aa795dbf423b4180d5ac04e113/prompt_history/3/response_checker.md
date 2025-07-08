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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state maps needed for this checker

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<WhileStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Off-by-One in Cleanup Loop")) {}

  void checkPreStmt(const WhileStmt *WS, CheckerContext &C) const;

private:
  // Helper function to check if the while loop condition has the pattern:
  // (--i > 0)
  bool isCleanupLoopCondition(const WhileStmt *WS, CheckerContext &C) const;
};

bool SAGenTestChecker::isCleanupLoopCondition(const WhileStmt *WS, CheckerContext &C) const {
  const Expr *Condition = WS->getCond();
  if (!Condition)
    return false;
  Condition = Condition->IgnoreParenCasts();

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Condition);
  if (!BO)
    return false;

  // Check that the binary operator is a '>' operator.
  if (BO->getOpcode() != BO_GT)
    return false;

  // Check the left-hand side: it should be a pre-decrement (i.e. --i)
  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO)
    return false;
  if (UO->getOpcode() != UO_PreDec)
    return false;

  // Ensure that the variable being decremented is named "i"
  const Expr *SubExpr = UO->getSubExpr()->IgnoreParenCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SubExpr);
  if (!DRE)
    return false;
  if (!ExprHasName(SubExpr, "i", C))
    return false;

  // Check the right-hand side: it must be the constant 0.
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
  llvm::APSInt Val;
  if (!EvaluateExprToInt(Val, RHS, C))
    return false;
  if (Val != 0)
    return false;

  return true;
}

void SAGenTestChecker::checkPreStmt(const WhileStmt *WS, CheckerContext &C) const {
  // Use our helper function to check for the specific pattern.
  if (!isCleanupLoopCondition(WS, C))
    return;

  // Optionally: Check the context to ensure we are inside an error-handling branch.
  // We could use findSpecificTypeInParents to ensure this while loop is contained
  // in an appropriate branch (e.g. an if-statement checking an error return).
  // For simplicity, we assume the unique pattern (--i > 0) in a while loop is enough.

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Off-by-one error: cleanup loop does not process the first resource", N);
  Report->addRange(WS->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects an off-by-one error in cleanup loop that skips the first resource", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```