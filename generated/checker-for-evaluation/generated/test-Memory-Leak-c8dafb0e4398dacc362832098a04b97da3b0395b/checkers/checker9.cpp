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

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: Map from req MemRegion to a cleanup flag.
// false means cleanup (hwrm_req_drop) has NOT been called.
REGISTER_MAP_WITH_PROGRAMSTATE(ReqStatusMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::PreCall, check::EndFunction> {
  
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Resource Leak", "Resource Cleanup")) {}

  // Callback for post-call: intercept hwrm_req_replace.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();

    // Identify call to hwrm_req_replace.
    const Expr *Origin = Call.getOriginExpr();
    if (!Origin)
      return;
    
    if (!ExprHasName(Origin, "hwrm_req_replace", C))
      return;
    
    // Evaluate the result of hwrm_req_replace.
    llvm::APSInt RetVal;
    if (!EvaluateExprToInt(RetVal, Origin, C))
      return;
    
    // If non-zero return code => error path.
    if (RetVal != 0) {
      // Retrieve the "req" pointer argument.
      // hwrm_req_replace(bp, req, fw_msg->msg, fw_msg->msg_len)
      const Expr *ReqExpr = Call.getArgExpr(1);
      if (!ReqExpr)
        return;
      const MemRegion *ReqMR = getMemRegionFromExpr(ReqExpr, C);
      if (!ReqMR)
        return;
      ReqMR = ReqMR->getBaseRegion();
      if (!ReqMR)
        return;
      // Record that cleanup is not yet done.
      State = State->set<ReqStatusMap>(ReqMR, false);
      C.addTransition(State);
    }
  }

  // Callback for pre-call: intercept hwrm_req_drop.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();

    const Expr *Origin = Call.getOriginExpr();
    if (!Origin)
      return;
    
    if (!ExprHasName(Origin, "hwrm_req_drop", C))
      return;
    
    // hwrm_req_drop is expected to be called with the req pointer as argument 0.
    const Expr *ReqExpr = Call.getArgExpr(0);
    if (!ReqExpr)
      return;
    const MemRegion *ReqMR = getMemRegionFromExpr(ReqExpr, C);
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;
    // If we had an entry for this req, mark it as cleaned up.
    const bool *HadLeak = State->get<ReqStatusMap>(ReqMR);
    if (HadLeak) {
      State = State->set<ReqStatusMap>(ReqMR, true);
      C.addTransition(State);
    }
  }

  // Callback for end of function: check if any req was not dropped.
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
    ProgramStateRef State = C.getState();

    // Retrieve the entire map.
    ProgramStateTrait<ReqStatusMap>::data_type Map = State->get<ReqStatusMap>();
    // Iterate over the map entries.
    for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
      // I->first is the req memory region, I->second is the cleanup flag.
      if (I->second == false) {
        // Found a req resource that was not dropped.
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          continue;
        auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Resource leak: Missing hwrm_req_drop() on error path", N);
        Report->addRange(RS->getSourceRange());
        C.emitReport(std::move(Report));
      }
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects resource leak where hwrm_req_drop() is missing on error path", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
