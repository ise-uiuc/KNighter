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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

//----------------------------------------------------------
// Customize program states: Map tracking whether the counter
// (datalen) has been updated for a given instance (base region).
//----------------------------------------------------------
REGISTER_MAP_WITH_PROGRAMSTATE(FlexCounterUpdatedMap, const MemRegion*, bool)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Flexible Array Counter Update Bug")) {}

  // Callback to intercept memcpy calls.
  // We expect that the destination of memcpy is the flexible-array member 'data'.
  // If so, we check that the corresponding counter (datalen) has been updated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to track binding operations.
  // Here we check for assignments to the field "datalen" and mark the
  // associated structure as having its counter updated.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report a bug when a flexible array member is accessed
  // prior to updating its counter field.
  void reportDelayedCounterUpdate(const CallEvent &Call, CheckerContext &C,
                                  const MemRegion *MR) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Check if the call is to memcpy.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "memcpy", C))
    return;

  // Retrieve the destination argument of memcpy (first argument).
  // We expect that this destination corresponds to the flexible-array 'data'.
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Check if this destination expression's source text contains "data".
  // If not, attempt to check its parents.
  if (!ExprHasName(DestExpr, "data", C)) {
    const Expr *ParentExpr = findSpecificTypeInParents<Expr>(DestExpr, C);
    if (!ParentExpr || !ExprHasName(ParentExpr, "data", C))
      return;
  }

  // Determine the memory region corresponding to the destination.
  const MemRegion *MR = getMemRegionFromExpr(DestExpr, C);
  if (!MR)
    return;

  // Get the base region, which should represent the instance of the structure.
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Query the program state for whether the counter field (datalen)
  // has been updated for this structure instance.
  ProgramStateRef State = C.getState();
  const bool *Updated = State->get<FlexCounterUpdatedMap>(MR);
  if (!Updated || !(*Updated)) {
    reportDelayedCounterUpdate(Call, C, MR);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  // Check if the binding is for the counter field "datalen".
  const Expr *LHSExpr = dyn_cast_or_null<Expr>(S);
  if (!LHSExpr)
    return;
  // Use the utility function to check if the left-hand expression contains "datalen".
  if (!ExprHasName(LHSExpr, "datalen", C))
    return;

  // Retrieve the memory region corresponding to "datalen".
  const MemRegion *MR = getMemRegionFromExpr(LHSExpr, C);
  if (!MR)
    return;
  // Use the base region (which represents the full event structure).
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark in the program state that the counter has been updated.
  ProgramStateRef State = C.getState();
  State = State->set<FlexCounterUpdatedMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::reportDelayedCounterUpdate(const CallEvent &Call, CheckerContext &C,
                                                    const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Flexible array counter (datalen) not updated before accessing flexible array member (data)", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects when a flexible-array member is accessed before its counter (datalen) is updated",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
