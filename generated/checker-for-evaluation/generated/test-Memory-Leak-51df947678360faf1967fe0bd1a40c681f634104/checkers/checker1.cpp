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

// Additional includes
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// In this checker we do not need extra program state tracking.
// We directly inspect the AST to see if free_netdev appears in the error branch.

namespace {

// A helper function to recursively search for a call to free_netdev within a statement.
bool containsFreeNetdevCall(const Stmt *S, CheckerContext &C) {
  if (!S)
    return false;

  // Check if this statement is a call expression.
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    const Expr *CalleeExpr = CE->getCallee();
    if (CalleeExpr && ExprHasName(CalleeExpr, "free_netdev", C))
      return true;
  }

  // Recursively check child statements.
  for (const Stmt *Child : S->children()) {
    if (containsFreeNetdevCall(Child, C))
      return true;
  }
  return false;
}

// The checker class
class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Missing free_netdev on error path")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper: report the bug.
  void reportMissingFree(const CallEvent &Call, CheckerContext &C, const IfStmt *IfS) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // We are interested in calls to rvu_rep_devlink_port_register.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "rvu_rep_devlink_port_register", C))
    return;

  // Evaluate the return value of rvu_rep_devlink_port_register.
  llvm::APSInt EvalRes;
  // Instead of using a non-existent CastToExpr, use OriginExpr directly.
  const Expr *RetExpr = OriginExpr;
  if (!RetExpr)
    return;
  if (!EvaluateExprToInt(EvalRes, RetExpr, C))
    return;

  // If return value indicates no error (0), then nothing to do.
  if (EvalRes == 0)
    return;

  // At this point, the function call returned an error.
  // We now try to locate the error branch for analysis.
  // Ascend the AST hierarchy from the call to look for an enclosing IfStmt.
  const IfStmt *EnclosingIf = findSpecificTypeInParents<IfStmt>(OriginExpr, C);
  if (!EnclosingIf)
    return;

  // For error returns, usually the check is "if (err)" so assume the then branch is the error branch.
  const Stmt *ThenBranch = EnclosingIf->getThen();
  if (!ThenBranch)
    return;

  // Check if free_netdev is called within the then branch.
  if (!containsFreeNetdevCall(ThenBranch, C)) {
    reportMissingFree(Call, C, EnclosingIf);
  }
}

void SAGenTestChecker::reportMissingFree(const CallEvent &Call, CheckerContext &C, const IfStmt *IfS) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing free_netdev on error path: allocated net_device is not freed when rvu_rep_devlink_port_register fails", N);
  Report->addRange(IfS->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing free_netdev call on error path when rvu_rep_devlink_port_register fails",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
