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
#include "clang/AST/Decl.h"
// Removed non-existent header: #include "clang/AST/MemberExpr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: a map to track whether num_trips has been initialized.
// The key is the memory region corresponding to the thermal_zone_device structure (tz).
REGISTER_MAP_WITH_PROGRAMSTATE(NumTripsInitMap, const MemRegion*, bool)
// Program state map to track pointer aliasing if needed.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Helper: Check if the given CallEvent represents a call to memcpy.
static bool isMemcpyCall(const CallEvent &Call) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  // Use the utility function for string matching.
  return ExprHasName(OriginExpr, "memcpy", const_cast<CheckerContext&>(*(Call.getCheckerContext())));
}

/// Helper: Report an initialization order bug.
static void reportInitOrderBug(const CallEvent &Call, CheckerContext &C,
                               const MemRegion *TZReg) {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *C.getBugReporter().getBugType("Initialization order error", "Initialization Order"),
      "Initialization order error: num_trips not set before memcpy", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

class SAGenTestChecker : public Checker<check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Initialization order error")) {}

  // Callback invoked after a function call is processed.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback invoked when a value is bound to a location.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper to mark that num_trips has been initialized for the given thermal zone (tz) region.
  ProgramStateRef markNumTripsInitialized(ProgramStateRef State, const MemRegion *TZReg) const {
    State = State->set<NumTripsInitMap>(TZReg, true);
    return State;
  }

  // Helper to update alias map for tracking, if needed.
  ProgramStateRef updateAlias(ProgramStateRef State, const MemRegion *Reg1, const MemRegion *Reg2) const {
    State = State->set<PtrAliasMap>(Reg1, Reg2);
    State = State->set<PtrAliasMap>(Reg2, Reg1);
    return State;
  }
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check if the binding is an assignment to a member field.
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(StoreE)) {
    // Check if the member being assigned is "num_trips"
    if (ME->getMemberDecl() && ME->getMemberDecl()->getNameAsString() == "num_trips") {
      // Get the base of the member expression, i.e. the thermal_zone_device structure pointer.
      const Expr *BaseExpr = ME->getBase()->IgnoreImplicit();
      const MemRegion *TZReg = getMemRegionFromExpr(BaseExpr, C);
      if (TZReg) {
        TZReg = TZReg->getBaseRegion();
        if (TZReg)
          State = markNumTripsInitialized(State, TZReg);
      }
    }
  }

  // Also update alias information if Loc and Val have associated regions.
  const MemRegion *LHSReg = Loc.getAsRegion();
  const MemRegion *RHSReg = Val.getAsRegion();
  if (LHSReg && RHSReg) {
    LHSReg = LHSReg->getBaseRegion();
    RHSReg = RHSReg->getBaseRegion();
    if (LHSReg && RHSReg)
      State = updateAlias(State, LHSReg, RHSReg);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Only care about memcpy calls.
  if (!isMemcpyCall(Call))
    return;

  // Retrieve the destination argument of memcpy.
  // memcpy(dest, src, n)
  if (Call.getNumArgs() < 1)
    return;
  
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Try to see if the destination comes from a member access corresponding to tz->trips.
  const Expr *E = DestExpr->IgnoreImplicit();
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->getMemberDecl() && ME->getMemberDecl()->getNameAsString() == "trips") {
      // Get the base region, which should be the thermal_zone_device structure.
      const Expr *BaseExpr = ME->getBase()->IgnoreImplicit();
      const MemRegion *TZReg = getMemRegionFromExpr(BaseExpr, C);
      if (!TZReg)
        return;
      TZReg = TZReg->getBaseRegion();
      if (!TZReg)
        return;
      // Check in the NumTripsInitMap whether num_trips has been initialized.
      const bool *Initialized = State->get<NumTripsInitMap>(TZReg);
      if (!Initialized || !(*Initialized)) {
        reportInitOrderBug(Call, C, TZReg);
      }
    }
  }
  // No transition change.
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects initialization order error: num_trips not set before memcpy in thermal_zone_device_register_with_trips", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
