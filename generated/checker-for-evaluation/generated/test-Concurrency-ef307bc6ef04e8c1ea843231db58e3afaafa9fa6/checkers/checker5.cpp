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
#include "clang/AST/Expr.h"  // Added to use dyn_cast<const Expr>
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/Lex/Lexer.h"  // for Lexer

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: Map the pointer region for "urb->hcpriv" 
// to a boolean value indicating safety (true means updated safely under lock,
// false means unsafely cleared outside of critical section).
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAssignState, const MemRegion*, bool)

namespace {

/// Utility: Check whether a given Stmt's source text contains a function call
/// to "spin_lock_irqsave", indicating that the assignment is done under lock.
static bool isUnderSpinLock(const Stmt *S, CheckerContext &C) {
  // Traverse upward in the AST for a CallExpr that contains "spin_lock_irqsave"
  const CallExpr *SpinLockCall = findSpecificTypeInParents<CallExpr>(S, C);
  if (SpinLockCall) {
    const Expr *Origin = SpinLockCall->getCallee();
    if (Origin && ExprHasName(Origin, "spin_lock_irqsave", C))
      return true;
  }
  return false;
}

/// Utility: Check whether an SVal represents a NULL constant.
static bool isNullVal(SVal Val, CheckerContext &C) {
  // The SVal method isZeroConstant() returns true if the value is a constant zero.
  return Val.isZeroConstant();
}

class SAGenTestChecker : public Checker<check::Bind, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Data race: unsynchronized pointer update")) {}

  // Callback invoked when a value is bound to a memory region.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Callback invoked just before a function call.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper for reporting the bug.
  void reportDataRace(const CallEvent &Call, CheckerContext &C,
                      const MemRegion *MR) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // Attempt to get the memory region from the left-hand side.
  const MemRegion *LHSRegion = Loc.getAsRegion();
  if (!LHSRegion)
    return;

  // Use getBaseRegion() to ensure we have the canonical region.
  LHSRegion = LHSRegion->getBaseRegion();
  if (!LHSRegion)
    return;

  // Check if the left-hand side expression contains "hcpriv".
  // This indicates an assignment to urb->hcpriv.
  const Expr *StoreExpr = dyn_cast<const Expr>(StoreE);
  if (!StoreExpr || !ExprHasName(StoreExpr, "hcpriv", C))
    return;

  // Check if the value being assigned is NULL.
  if (!isNullVal(Val, C))
    return;

  // Determine if this binding occurs inside a critical section.
  bool safeAssignment = isUnderSpinLock(StoreE, C);
  
  // Update the program state for this pointer region.
  State = State->set<PtrAssignState>(LHSRegion, safeAssignment);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Look for calls to dwc2_hcd_urb_dequeue.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "dwc2_hcd_urb_dequeue", C))
    return;

  // According to the bug pattern, the second parameter of dwc2_hcd_urb_dequeue
  // is expected to be urb->hcpriv.
  if (Call.getNumArgs() < 2)
    return;

  SVal ArgVal = Call.getArgSVal(1);
  const MemRegion *Region = ArgVal.getAsRegion();
  if (!Region)
    return;
  Region = Region->getBaseRegion();
  if (!Region)
    return;

  // Look up the pointer's assignment state.
  const bool *Safe = State->get<PtrAssignState>(Region);
  // If the stored state exists and it indicates an unsafe (false) assignment,
  // report a data race.
  if (Safe && (*Safe == false)) {
    reportDataRace(Call, C, Region);
  }
}

void SAGenTestChecker::reportDataRace(const CallEvent &Call, CheckerContext &C,
                                      const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Data race: urb->hcpriv is cleared outside a locked region", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects data race from unsynchronized clearing and later use of urb->hcpriv", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
