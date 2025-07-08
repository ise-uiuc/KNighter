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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

//
// No custom program state maps are needed for this checker.
//

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Premature work data read", 
                       "Ordering Issue")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // No additional helper functions are needed.
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                              CheckerContext &C) const {
  if (!Condition)
    return;

  // We expect the condition to be an expression.
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  // Check if the condition's source text contains "from_cancel".
  // This indicates that the condition is testing for cancellation.
  if (!ExprHasName(CondExpr, "from_cancel", C))
    return;

  // Retrieve the enclosing compound statement.
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(Condition, C);
  if (!CS)
    return;

  // Get the begin location of the condition.
  const SourceManager &SM = C.getSourceManager();
  SourceLocation CondLoc = CondExpr->getBeginLoc();

  // Iterate over the statements in the compound statement to inspect ordering.
  bool FoundPrematureRead = false;
  for (const Stmt *S : CS->body()) {
    // Only examine statements that occur before the branch condition.
    if (S->getEndLoc().isValid() && SM.isBeforeInTranslationUnit(S->getEndLoc(), CondLoc)) {
      // If the statement's source text mentions "work_data_bits", it likely contains the read.
      if (ExprHasName(S, "work_data_bits", C)) {
        FoundPrematureRead = true;
        break;
      }
    }
  }

  // If a premature read is detected, report a bug.
  if (FoundPrematureRead) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Premature read of work data before cancellation check", N);
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects premature read of work data before checking from_cancel",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```