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
#include "clang/AST/Stmt.h"  // Replaced "clang/AST/IfStmt.h" with "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
// (Additional includes if necessary)

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Resource Leak", "Memory Leak")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function can be defined if additional processing needed.
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression of the call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Verify that the call is to rvu_rep_devlink_port_register.
  if (!ExprHasName(OriginExpr, "rvu_rep_devlink_port_register", C))
    return;
  
  // At this point we know that rvu_rep_devlink_port_register was called.
  // Typically its return value is checked (e.g. if(err)) and in the error branch
  // the allocated net_device should be freed via free_netdev().
  // We attempt to locate the enclosing if-stmt that checks the return value.
  const IfStmt *EnclosingIf = findSpecificTypeInParents<IfStmt>(OriginExpr, C);
  if (!EnclosingIf)
    return;

  // Get the 'then' branch of the if-statement where the error handling occurs.
  const Stmt *ThenBranch = EnclosingIf->getThen();
  if (!ThenBranch)
    return;

  // Look downward in the then branch for a call expression.
  // We use the provided utility function to find one instance of a CallExpr.
  const CallExpr *FoundCall = findSpecificTypeInChildren<CallExpr>(ThenBranch);
  bool FreeCalled = false;
  if (FoundCall) {
    // Check if the callee of the found call is free_netdev.
    // Note: We do not call IgnoreImplicit() because getMemRegionFromExpr() requires the original expression.
    if (ExprHasName(FoundCall->getCallee(), "free_netdev", C))
      FreeCalled = true;
  }
  
  // If we did not find a free_netdev call in the error handling branch, report a resource leak.
  if (!FreeCalled) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Resource leak: netdev not freed on error path", N);
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects missing free_netdev() call when rvu_rep_devlink_port_register fails, "
      "leading to a resource leak", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
