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

// Add any additional includes if necessary.
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track pending request regions.
// The map records a MemRegion* (request pointer) and a boolean value:
// false means the resource is still pending clean-up, true means it has been released.
REGISTER_MAP_WITH_PROGRAMSTATE(PendingReqMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Missing request cleanup", "Resource Leak")) {}

  // Callback: process function calls (post-call) to track allocation and cleanup.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: at function end, check for any pending (unreleased) resources.
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportLeak(const MemRegion *MR, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use ExprHasName for checking function name.
  if (ExprHasName(OriginExpr, "hwrm_req_init", C)) {
    // In the call: hwrm_req_init(bp, req, ...), the "req" is the 2nd parameter (index 1)
    if (Call.getNumArgs() < 2)
      return;
    SVal reqVal = Call.getArgSVal(1);
    const MemRegion *ReqMR = reqVal.getAsRegion();
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;
    // Mark the request as pending (false means not yet cleaned up)
    State = State->set<PendingReqMap>(ReqMR, false);
    C.addTransition(State);
  } else if (ExprHasName(OriginExpr, "hwrm_req_drop", C)) {
    // In the call: hwrm_req_drop(bp, req), the "req" is the 2nd parameter (index 1)
    if (Call.getNumArgs() < 2)
      return;
    SVal reqVal = Call.getArgSVal(1);
    const MemRegion *ReqMR = reqVal.getAsRegion();
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;
    // Mark the request as cleaned up. We can either remove the entry or mark it as true.
    // Here, we mark it as cleaned up.
    State = State->set<PendingReqMap>(ReqMR, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Check that we are in the scope of the target function bnxt_send_msg.
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  if (FD->getNameAsString() != "bnxt_send_msg")
    return;

  ProgramStateRef State = C.getState();
  // Retrieve the PendingReqMap from the state.
  const auto PendingMap = State->get<PendingReqMap>();
  // Iterate over each entry in PendingReqMap.
  for (const auto &Entry : PendingMap) {
    // If the boolean is false, then the resource was not cleaned up.
    if (!Entry.second) {
      // Report the bug on the first leaked resource found.
      reportLeak(Entry.first, C);
      break;
    }
  }
}

void SAGenTestChecker::reportLeak(const MemRegion *MR, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing cleanup call for allocated request: potential memory leak", N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects missing hwrm_req_drop() call on error paths after resource allocation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
