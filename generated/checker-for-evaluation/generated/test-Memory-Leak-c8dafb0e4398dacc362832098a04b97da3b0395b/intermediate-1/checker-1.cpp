#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

// Register a program state map to track allocated request objects.
// The key is the MemRegion* representing the request and the value indicates
// whether cleanup was performed (true) or not (false).
REGISTER_MAP_WITH_PROGRAMSTATE(RequestAllocMap, const MemRegion*, bool)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Missing cleanup", "Resource Leak")) {}

  // Callback function: invoked after a call returns.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report a potential leak.
  void reportLeak(const MemRegion *ReqReg, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Use utility function ExprHasName for accurate function name verification.
  // Case 1: hwrm_req_init -- track allocation of a request.
  if (ExprHasName(Origin, "hwrm_req_init", C)) {
    llvm::APSInt RetVal;
    // Only track if the call returned success (i.e. return 0).
    if (EvaluateExprToInt(RetVal, cast<CallExpr>(Origin), C) && RetVal == 0) {
      // The allocated request is typically passed as the second argument (index 1).
      const Expr *ReqArg = Call.getArgExpr(1);
      if (!ReqArg)
        return;
      const MemRegion *ReqReg = getMemRegionFromExpr(ReqArg, C);
      if (!ReqReg)
        return;
      ReqReg = ReqReg->getBaseRegion();
      if (!ReqReg)
        return;
      // Record the new allocation as not yet cleaned (false).
      State = State->set<RequestAllocMap>(ReqReg, false);
      C.addTransition(State);
    }
    return;
  }

  // Case 2: hwrm_req_drop -- indicate that the request has been cleaned.
  if (ExprHasName(Origin, "hwrm_req_drop", C)) {
    // Assume the request is the second argument (index 1).
    const Expr *ReqArg = Call.getArgExpr(1);
    if (!ReqArg)
      return;
    const MemRegion *ReqReg = getMemRegionFromExpr(ReqArg, C);
    if (!ReqReg)
      return;
    ReqReg = ReqReg->getBaseRegion();
    if (!ReqReg)
      return;
    // Mark the request as cleaned.
    State = State->set<RequestAllocMap>(ReqReg, true);
    C.addTransition(State);
    return;
  }

  // Case 3: hwrm_req_replace -- if it fails, check for missing cleanup.
  if (ExprHasName(Origin, "hwrm_req_replace", C)) {
    llvm::APSInt RetVal;
    // If the call returns an error (non-zero value)
    if (EvaluateExprToInt(RetVal, cast<CallExpr>(Origin), C) && RetVal != 0) {
      // Get the "req" pointer from the second argument.
      const Expr *ReqArg = Call.getArgExpr(1);
      if (!ReqArg)
        return;
      const MemRegion *ReqReg = getMemRegionFromExpr(ReqArg, C);
      if (!ReqReg)
        return;
      ReqReg = ReqReg->getBaseRegion();
      if (!ReqReg)
        return;
      // Check if the RequestAllocMap has this region still marked as not cleaned.
      const bool *Cleaned = State->get<RequestAllocMap>(ReqReg);
      if (Cleaned && *Cleaned == false) {
        reportLeak(ReqReg, C);
      }
    }
    return;
  }
}

void SAGenTestChecker::reportLeak(const MemRegion *ReqReg, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing cleanup: hwrm_req_drop not called on error path", N);
  // Optionally, one could add additional range information.
  // The following code was removed because CheckerContext::getSVal does not accept a MemRegion.
  // Report->addRange(C.getSVal(ReqReg, C.getLocationContext()).getAsRegion()->getLocation());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects failure to properly clean up allocated requests when hwrm_req_replace fails",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
