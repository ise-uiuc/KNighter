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
#include "clang/Lex/Lexer.h"
#include <llvm/ADT/ImmutableMap.h>

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: track request pointers that need cleanup.
// The bool value indicates whether hwrm_req_drop has been called on the region:
//   true  => cleanup has been performed,
//   false => still pending cleanup.
REGISTER_MAP_WITH_PROGRAMSTATE(ReqCleanupMap, const MemRegion *, bool)
// Optionally, track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::PreStmt<ReturnStmt>, check::Bind > {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Resource Leak",
                                         "Allocated resource not cleaned on error path")) {}

  // Callback: Intercept function calls to track allocation and cleanup.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: Check at each return statement that all allocated resources were cleaned.
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

  // Callback: Track pointer aliasing when a pointer is copied.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper: Report a resource leak for the given memory region.
  void reportResourceLeak(const MemRegion *MR, const ReturnStmt *RS, CheckerContext &C) const;
};

/// checkPostCall:
///  - For a call to hwrm_req_init: record the allocated request (the 2nd argument)
///    with an initial cleanup flag 'false'.
///  - For a call to hwrm_req_drop: mark the corresponding request (the 2nd argument)
///    as cleaned (true).
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check for hwrm_req_init.
  if (ExprHasName(OriginExpr, "hwrm_req_init", C)) {
    // Expecting the second argument (index 1) to be the 'req' pointer.
    if (Call.getNumArgs() <= 1)
      return;
    SVal ReqArgVal = Call.getArgSVal(1);
    const MemRegion *MR = getMemRegionFromExpr(nullptr, C);
    // Retrieve the region from the expression argument.
    MR = ReqArgVal.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Mark the resource as not cleaned.
    State = State->set<ReqCleanupMap>(MR, false);
    C.addTransition(State);
    return;
  }

  // Check for hwrm_req_drop.
  if (ExprHasName(OriginExpr, "hwrm_req_drop", C)) {
    // Expecting the second argument (index 1) to be the request pointer.
    if (Call.getNumArgs() <= 1)
      return;
    SVal ReqArgVal = Call.getArgSVal(1);
    const MemRegion *MR = ReqArgVal.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Mark the resource as cleaned.
    State = State->set<ReqCleanupMap>(MR, true);
    C.addTransition(State);
    return;
  }

  // For hwrm_req_replace, we do not update the cleanup flag.
  // In the buggy scenario, an error return (non-zero rc) from hwrm_req_replace
  // leads directly to a return without calling hwrm_req_drop.
}

/// checkPreStmt:
/// At every return statement, inspect the state and report any allocated request
/// that has not been cleaned up.
void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Retrieve the entire ReqCleanupMap.
  llvm::ImmutableMap<const MemRegion*, bool> LeakMap = State->get<ReqCleanupMap>();
  if (LeakMap.isEmpty())
    return;
  
  // Iterate over all tracked request regions.
  for (const auto &Entry : LeakMap) {
    const MemRegion *MR = Entry.first;
    bool Cleaned = Entry.second;
    // If the resource is still marked as not cleaned,
    // generate a bug report.
    if (!Cleaned) {
      reportResourceLeak(MR, RS, C);
    }
  }
}

/// checkBind:
/// Update aliasing information when a pointer is copied.  If a request pointer
/// is assigned from one variable to another, record their alias relationship.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;
  
  // Record the alias relationship in both directions.
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  C.addTransition(State);
}

/// reportResourceLeak:
/// Emit a warning for a leaked resource that was not cleaned up on an error path.
void SAGenTestChecker::reportResourceLeak(const MemRegion *MR, const ReturnStmt *RS,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential memory leak: allocated request not freed on error path", N);
  Report->addRange(RS->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects missing cleanup of allocated requests (hwrm_req_init not dropped on error paths)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
