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

#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

//--------------------------------------------------------------------------
// No extra program state maps are needed for this checker.
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
// Helper function that recursively checks if a statement contains a call
// to a function named "free_netdev".
//--------------------------------------------------------------------------
bool containsFreeNetdev(const Stmt *S, CheckerContext &C) {
  if (!S)
    return false;
  
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    // Use the utility function to check if the call expression's
    // source text contains "free_netdev".
    if (ExprHasName(CE, "free_netdev", C))
      return true;
  }
  
  // Recursively check child statements.
  for (const Stmt *Child : S->children()) {
    if (containsFreeNetdev(Child, C))
      return true;
  }
  
  return false;
}

namespace {

//--------------------------------------------------------------------------
// Checker: SAGenTestChecker
//
// This checker detects the resource leak bug pattern where, on an error
// path after calling rvu_rep_devlink_port_register(), the allocated net_device 
// (created by alloc_etherdev) is not freed via free_netdev.
// 
// The checker uses checkPostCall to intercept the call to
// rvu_rep_devlink_port_register(), then locates an enclosing if-statement
// testing a variable (named "err") for failure. It scans the error-handling 
// branch (the "then" branch) to determine if it contains a call to free_netdev.
// If not, it reports a potential leak.
//--------------------------------------------------------------------------
class SAGenTestChecker 
    : public Checker< check::PostCall > {
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Resource Leak", "Resource management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

  
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Get the original call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  const IdentifierInfo *CalleeID = Call.getCalleeIdentifier();
  if (!CalleeID)
    return;
  
  StringRef CalleeName = CalleeID->getName();
  
  // We are interested in the call to rvu_rep_devlink_port_register.
  if (CalleeName != "rvu_rep_devlink_port_register")
    return;
  
  // Locate an enclosing if-statement that checks the return error.
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(OriginExpr, C);
  if (!IfS)
    return;
  
  // Check if the if-statement's condition seems to be testing an error code.
  const Expr *CondExpr = IfS->getCond();
  if (!CondExpr)
    return;
  
  // Use ExprHasName to see if the condition text contains "err".
  if (!ExprHasName(CondExpr, "err", C))
    return;
  
  // In an error-handling branch, we expect free_netdev to be called to
  // release the allocated net_device.
  const Stmt *ThenBranch = IfS->getThen();
  if (!ThenBranch)
    return;
  
  // If the "then" branch does not contain a call to free_netdev (using our
  // recursive helper), then report a bug.
  if (!containsFreeNetdev(ThenBranch, C)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Resource not freed on error path after rvu_rep_devlink_port_register failure",
        N);
    Report->addRange(OriginExpr->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects failure to free allocated net_device on the error path in rvu_rep_create",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
