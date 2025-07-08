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

// Declare a program state map that tracks an allocated request and whether it was cleaned-up.
// The key is the base region corresponding to the req pointer.
REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedReqMap, const MemRegion*, bool)
// Map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

// This checker detects resource leaks when a request allocated via hwrm_req_init
// is not properly released via hwrm_req_drop before an error return.
class SAGenTestChecker : public Checker< check::PostCall, check::EndFunction, check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Resource Leak", "Resource Cleanup")) {}

  // Called after function calls are executed.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Called when the function analysis is complete.
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  // Called on binding (assignment) to track aliasing relationships.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report a resource leak.
  void reportLeak(CheckerContext &C, const MemRegion *MR, const char *Msg) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Identify calls to hwrm_req_init.  Its signature is assumed to be:
  //   int hwrm_req_init(bp, req, ...);
  // and the 'req' pointer is passed as the second argument (index 1).
  if (const IdentifierInfo *II = Call.getCalleeIdentifier()) {
    StringRef FnName = II->getName();

    if (FnName == "hwrm_req_init") {
      // For hwrm_req_init, we want to register the allocated request pointer in our state.
      // Retrieve the 'req' argument.
      if (Call.getNumArgs() < 2)
        return;
      SVal ReqVal = Call.getArgSVal(1);
      const MemRegion *MR = ReqVal.getAsRegion();
      if (!MR)
        return;
      MR = MR->getBaseRegion();
      if (!MR)
        return;
      // We assume the call succeeded and the allocation happened.
      // Mark this region as "not cleaned" (false) initially.
      State = State->set<AllocatedReqMap>(MR, false);
      C.addTransition(State);
      return;
    }

    // Identify calls to hwrm_req_drop.
    // Its signature is assumed to be:
    //   void hwrm_req_drop(bp, req);
    // where the req pointer is the second argument (index 1).
    if (FnName == "hwrm_req_drop") {
      if (Call.getNumArgs() < 2)
        return;
      SVal ReqVal = Call.getArgSVal(1);
      const MemRegion *MR = ReqVal.getAsRegion();
      if (!MR)
        return;
      MR = MR->getBaseRegion();
      if (!MR)
        return;
      // Mark this allocated resource as cleaned.
      State = State->set<AllocatedReqMap>(MR, true);
      C.addTransition(State);
      return;
    }
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Retrieve the map of allocated request objects.
  const auto AllocMap = State->get<AllocatedReqMap>();
  // Iterate over all tracked allocations.
  for (const auto &Entry : AllocMap) {
    // Entry.first is the MemRegion*, Entry.second is a bool indicating if it was cleaned.
    if (!Entry.second) {
      // Report the leak on the current end of function.
      const MemRegion *MR = Entry.first;
      reportLeak(C, MR, "Resource leak: allocated request not freed on error path");
      // Report once per leaked resource.
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // This function tracks aliasing relationships.
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;
  if (const MemRegion *RHSReg = Val.getAsRegion()) {
    RHSReg = RHSReg->getBaseRegion();
    if (!RHSReg)
      return;
    // Record the aliasing relationship in both directions.
    State = State->set<PtrAliasMap>(LHSReg, RHSReg);
    State = State->set<PtrAliasMap>(RHSReg, LHSReg);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportLeak(CheckerContext &C, const MemRegion *MR, const char *Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  // Create a bug report using the PathSensitiveBugReport constructor.
  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  // The current API does not support adding a source range from MemRegion,
  // so we omit adding the source range to the bug report.
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects resource leak when allocated request is not freed on error paths",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
