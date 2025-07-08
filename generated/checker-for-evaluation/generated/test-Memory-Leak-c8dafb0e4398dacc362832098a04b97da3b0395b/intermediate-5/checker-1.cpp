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
#include <memory>

// No specialized program state maps are required for this checker.

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper function: Given a branch statement, check if it contains a call to hwrm_req_drop.
static bool hasCleanupCall(const Stmt *branch, CheckerContext &C) {
  // Use the utility function to search downward in the AST from the branch.
  if (!branch)
    return false;

  // Find a CallExpr somewhere in the branch.
  const CallExpr *foundCall = findSpecificTypeInChildren<CallExpr>(branch);
  if (!foundCall)
    return false;
  // Check if the call's callee source text contains "hwrm_req_drop".
  // It is possible that the found call is not the desired one. In a more
  // complete implementation one would iterate over all such calls.
  if (const Expr *calleeExpr = foundCall->getCallee()) {
    if (ExprHasName(calleeExpr, "hwrm_req_drop", C))
      return true;
  }
  return false;
}

// Helper function: Report a bug at a specific location.
static void reportCleanupLeak(const Stmt *S, CheckerContext &C) {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *C.getBugReporter().getOrCreateBugType("Resource leak: Missing hwrm_req_drop cleanup on error path"),
      "Resource leak: Missing hwrm_req_drop cleanup on error path", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

class SAGenTestChecker
    : public Checker<check::BranchCondition, check::PostStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Resource leak: Missing cleanup call")) {}

  // Callback for branch conditions.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    // We first check if the condition's source text contains "hwrm_req_replace".
    // This indicates that the if-statement is testing the return value
    // of hwrm_req_replace.
    if (!Condition)
      return;
    if (!ExprHasName(cast<Expr>(Condition), "hwrm_req_replace", C))
      return;

    // Climb up to find the corresponding if-statement.
    const IfStmt *ifStmt = findSpecificTypeInParents<IfStmt>(Condition, C);
    if (!ifStmt)
      return;

    // Retrieve the "then" branch of the if-statement.
    const Stmt *thenBranch = ifStmt->getThen();
    if (!thenBranch)
      return;

    // If the "then" branch does not contain a call to hwrm_req_drop, then
    // on error path the cleanup is missing.
    if (!hasCleanupCall(thenBranch, C)) {
      reportCleanupLeak(thenBranch, C);
    }
  }

  // Callback for ReturnStmt nodes.
  void checkPostStmt(const ReturnStmt *RS, CheckerContext &C) const {
    if (!RS)
      return;
    // Look upward in the AST for an enclosing if-statement.
    const IfStmt *ifStmt = findSpecificTypeInParents<IfStmt>(RS, C);
    if (!ifStmt)
      return;
    // Check if the if-statement's condition involves hwrm_req_replace.
    const Expr *condExpr = ifStmt->getCond();
    if (!condExpr)
      return;
    if (!ExprHasName(condExpr, "hwrm_req_replace", C))
      return;

    // Retrieve the "then" branch and check if it contains hwrm_req_drop.
    const Stmt *thenBranch = ifStmt->getThen();
    if (!thenBranch)
      return;

    if (!hasCleanupCall(thenBranch, C)) {
      reportCleanupLeak(RS, C);
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects resource leak due to missing hwrm_req_drop cleanup on error paths after hwrm_req_replace",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
