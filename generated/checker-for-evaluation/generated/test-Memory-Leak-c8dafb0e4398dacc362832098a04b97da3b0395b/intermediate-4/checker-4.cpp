#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map which tracks for each "req" memory region whether
// it is pending cleanup (true) or has already been cleaned-up.
REGISTER_MAP_WITH_PROGRAMSTATE(ReqCleanupMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(new BugType(this, "Resource Leak", "Resource Cleanup")) {}

  // Callback to catch calls to hwrm_req_replace and hwrm_req_drop.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback invoked at the end of a function where we check for pending resource cleanups.
  // Updated signature to match Clang-18 API.
  void checkEndFunction(CheckerContext &C) const;

private:
  // (Optional helper function for reporting, if needed in the future)
  void reportLeak(const MemRegion *MR, CheckerContext &C, const CallEvent *Call) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  const IdentifierInfo *CalleeII = Call.getCalleeIdentifier();
  if (!CalleeII)
    return;
  StringRef CalleeName = CalleeII->getName();

  // --- Handle hwrm_req_replace ---
  // In the firmware call hwrm_req_replace(bp, req, msg, msg_len):
  // If the function returns a nonzero value (error code), the request 'req'
  // must be cleaned up later; therefore, we record it.
  if (CalleeName == "hwrm_req_replace") {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, OriginExpr, C)) {
      if (EvalRes != 0) { // An error occurred.
        // "req" is the second argument (argument index 1).
        const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
        if (!CE || CE->getNumArgs() < 2)
          return;
        const Expr *ReqArg = CE->getArg(1);
        const MemRegion *ReqRegion = getMemRegionFromExpr(ReqArg, C);
        if (!ReqRegion)
          return;
        ReqRegion = ReqRegion->getBaseRegion();
        if (!ReqRegion)
          return;
        // Mark this req as pending cleanup.
        State = State->set<ReqCleanupMap>(ReqRegion, true);
        C.addTransition(State);
      }
    }
  }
  // --- Handle hwrm_req_drop ---
  // The function hwrm_req_drop(bp, req) is used to release the request.
  // When it is called, we remove the "pending cleanup" marker for the req.
  else if (CalleeName == "hwrm_req_drop") {
    const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
    if (!CE || CE->getNumArgs() < 2)
      return;
    const Expr *ReqArg = CE->getArg(1);
    const MemRegion *ReqRegion = getMemRegionFromExpr(ReqArg, C);
    if (!ReqRegion)
      return;
    ReqRegion = ReqRegion->getBaseRegion();
    if (!ReqRegion)
      return;
    if (State->contains<ReqCleanupMap>(ReqRegion))
      State = State->remove<ReqCleanupMap>(ReqRegion);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Retrieve the current ReqCleanupMap.
  auto ReqMap = State->get<ReqCleanupMap>();
  // Iterate over every tracked req.
  for (auto It = ReqMap.begin(), End = ReqMap.end(); It != End; ++It) {
    // If the cleanup flag is still true, then hwrm_req_drop was not called.
    if (It->second) {
      const MemRegion *ReqRegion = It->first;
      ExplodedNode *N = C.generateErrorNode();
      if (!N)
        continue;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Missing hwrm_req_drop on error path – potential memory leak", N);
      // Highlight the location associated with the end of the function.
      // Here we use the source range of the current function declaration.
      if (const Decl *D = C.getLocationContext()->getDecl())
        Report->addRange(D->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}

void SAGenTestChecker::reportLeak(const MemRegion *MR, CheckerContext &C, const CallEvent *Call) const {
  // (Optional helper in case more elaborate reporting is required.)
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Resource leak: allocated request not cleaned up on error path", N);
  if (Call)
    Report->addRange(Call->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing cleanup of request resources when hwrm_req_replace fails",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
