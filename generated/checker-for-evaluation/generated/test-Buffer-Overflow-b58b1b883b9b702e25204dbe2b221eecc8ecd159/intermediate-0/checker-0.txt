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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

//
// No custom program state maps are needed for this checker.
//

namespace {

class SAGenTestChecker : public Checker< check::PreStmt<CompoundAssignOperator> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unsigned counter underflow", "Logic Error")) {}

  // Callback: Invoked just before a CompoundAssignOperator is processed.
  // We are interested in subtraction assignments (i.e. -=) that update iter->count.
  void checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const;

private:
  // Helper method to check if a guarding if-statement exists.
  // It checks upward in the AST for an IfStmt whose condition (as source text)
  // contains a check of the form "shorten >= iter->count".
  bool isGuarded(const CompoundAssignOperator *CAO, CheckerContext &C) const;
};

bool SAGenTestChecker::isGuarded(const CompoundAssignOperator *CAO, CheckerContext &C) const {
  // Walk upward to look for an enclosing if-statement.
  const IfStmt *ifStmt = findSpecificTypeInParents<IfStmt>(CAO, C);
  if (!ifStmt)
    return false;
  
  const Expr *condExpr = ifStmt->getCond();
  if (!condExpr)
    return false;
  
  // Extract source text from the condition.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange condRange = CharSourceRange::getTokenRange(condExpr->getSourceRange());
  StringRef condText = Lexer::getSourceText(condRange, SM, LangOpts);
  
  // Look for the pattern: a '>=' comparison that involves "shorten" and "iter" (and "count")
  if (condText.contains(">=") &&
      condText.contains("shorten") &&
      condText.contains("iter") &&
      condText.contains("count"))
    return true;
  
  return false;
}

void SAGenTestChecker::checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const {
  // We are only interested in subtraction assignments
  if (CAO->getOpcode() != BO_SubAssign)
    return;
  
  // Examine the left-hand side of the "-=" operator.
  // We expect it to be a member access of the form iter->count.
  const Expr *lhs = CAO->getLHS()->IgnoreParenCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(lhs);
  if (!ME)
    return;
  
  // Verify that the member being accessed is named "count".
  std::string memberName = ME->getMemberNameInfo().getAsString();
  if (memberName != "count")
    return;
  
  // Check that the base of the member expression has the name "iter".
  // (Using our utility function ExprHasName to examine the source text.)
  const Expr *baseExpr = ME->getBase()->IgnoreParenCasts();
  if (!ExprHasName(baseExpr, "iter", C))
    return;
  
  // Examine the right-hand side which should involve the computed adjustment value.
  // We expect it to reference "shorten".
  const Expr *rhs = CAO->getRHS()->IgnoreParenCasts();
  if (!ExprHasName(rhs, "shorten", C))
    return;
  
  // Check if there is a protecting if-statement that verifies that shorten is less than iter->count.
  if (isGuarded(CAO, C))
    return; // The subtraction is guarded; no bug to report.
  
  // If we reach here, no guarding check was found.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential unsigned underflow: subtracting adjustment value from iter->count "
      "without verifying it is smaller",
      N);
  report->addRange(CAO->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential unsigned underflow when subtracting shorten from iter->count without proper checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
