#include "clang/AST/Expr.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace taint;

//--------------------------------------------------------------------------
// Customize Program States
//--------------------------------------------------------------------------
REGISTER_MAP_WITH_PROGRAMSTATE(DevmAllocMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::PreCall, check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Double free of devm_* allocated memory")) {}

  // Callback to model allocations via devm_kcalloc
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // Identify devm_kcalloc calls via the origin expression.
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;
    if (!ExprHasName(OriginExpr, "devm_kcalloc", C))
      return;

    // Get the call expression and its memory region.
    const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
    if (!CE)
      return;
    const MemRegion *MR = getMemRegionFromExpr(CE, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Mark that this region is managed by devm_*.
    State = State->set<DevmAllocMap>(MR, true);
    C.addTransition(State);
  }

  // Callback to inspect deallocation calls.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // Check for free functions that may cause a double free.
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;
    // Check if the function name is pinctrl_utils_free_map or
    // pinconf_generic_dt_free_map.
    if (! (ExprHasName(OriginExpr, "pinctrl_utils_free_map", C) ||
           ExprHasName(OriginExpr, "pinconf_generic_dt_free_map", C)))
      return;
    if (Call.getNumArgs() == 0)
      return;
    // Get the pointer argument to be freed.
    SVal ArgVal = Call.getArgSVal(0);
    const MemRegion *MR = ArgVal.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Check if this region has been allocated via a devm_* routine.
    const bool *Managed = State->get<DevmAllocMap>(MR);
    if (Managed && *Managed == true) {
      reportDoubleFree(MR, C);
    }
  }

  // Callback to track pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // If binding involves memory regions, record the alias.
    const MemRegion *LHS = Loc.getAsRegion();
    if (!LHS)
      return;
    LHS = LHS->getBaseRegion();
    if (!LHS)
      return;
    const MemRegion *RHS = Val.getAsRegion();
    if (!RHS)
      return;
    RHS = RHS->getBaseRegion();
    if (!RHS)
      return;
    // Record aliasing in both directions.
    State = State->set<PtrAliasMap>(LHS, RHS);
    State = State->set<PtrAliasMap>(RHS, LHS);
    C.addTransition(State);
  }

private:
  // Helper to report the double free error.
  void reportDoubleFree(const MemRegion *MR, CheckerContext &C) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Double free of devm_* allocated memory", N);
    C.emitReport(std::move(report));
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects double free of memory allocated by a devm_* allocator", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
