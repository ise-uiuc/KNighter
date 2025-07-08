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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

// Register program state map to record for each event object whether its
// size field (datalen) has been updated.
REGISTER_MAP_WITH_PROGRAMSTATE(DatalenUpdatedMap, const MemRegion *, bool)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker :
    public Checker<check::Bind, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker()
      : BT(new BugType(this, "Flexible Array Access Before Size Update")) {}

  // Called when a value is bound to a location.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Called after a function call (e.g., memcpy) is processed.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper to report the bug.
  void reportFlexibleArrayBug(const MemRegion *MR, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                   CheckerContext &C) const {
  // We want to catch assignments to the size field ("datalen")
  // Use the utility function ExprHasName to check whether the left-hand side expression
  // refers to the "datalen" member.
  if (!StoreE)
    return;
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(StoreE)) {
    if (ExprHasName(ME, "datalen", C)) {
      // Get the base expression of the member access, which should be the event pointer.
      const Expr *BaseExpr = ME->getBase();
      if (!BaseExpr)
        return;
      // Retrieve event's memory region.
      const MemRegion *EventMR = getMemRegionFromExpr(BaseExpr, C);
      if (!EventMR)
        return;
      EventMR = EventMR->getBaseRegion();
      if (!EventMR)
        return;
      // Mark the event's datalen as updated.
      ProgramStateRef State = C.getState();
      State = State->set<DatalenUpdatedMap>(EventMR, true);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  // Intercept calls to memcpy.
  const IdentifierInfo *CalleeII = Call.getCalleeIdentifier();
  if (!CalleeII)
    return;
  if (CalleeII->getName() != "memcpy")
    return;

  // Get the destination argument of memcpy.
  const Expr *DstExpr = Call.getArgExpr(0);
  if (!DstExpr)
    return;

  // Check if the destination expression accesses "data" (flexible array member).
  if (!ExprHasName(DstExpr, "data", C))
    return;

  // Retrieve the event object's memory region associated with the destination.
  const MemRegion *EventMR = getMemRegionFromExpr(DstExpr, C);
  if (!EventMR)
    return;
  EventMR = EventMR->getBaseRegion();
  if (!EventMR)
    return;

  // Check whether the datalen field was updated for this event object.
  ProgramStateRef State = C.getState();
  const bool *Updated = State->get<DatalenUpdatedMap>(EventMR);
  if (!Updated || !(*Updated))
    reportFlexibleArrayBug(EventMR, C);
}

void SAGenTestChecker::reportFlexibleArrayBug(const MemRegion *MR,
                                              CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Flexible array member accessed before size (datalen) is updated", ErrNode);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects access to a flexible array member before updating its size field",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
