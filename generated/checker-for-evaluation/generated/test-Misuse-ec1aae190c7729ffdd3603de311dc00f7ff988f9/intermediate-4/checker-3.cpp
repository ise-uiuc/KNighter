#include <memory>
#include "llvm/Support/Casting.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
// Removed unused taint include if not required by the checker implementation.
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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;

// Register a program state map that maps an event's MemRegion to a bool flag
// indicating whether the metadata update (datalen update) has been performed.
// false: not yet updated; true: updated.
REGISTER_MAP_WITH_PROGRAMSTATE(FlexArrayUpdateMap, const MemRegion*, bool)

// The checker will use three callbacks: checkPostCall, checkBind, and checkPreCall.
namespace {

class SAGenTestChecker 
  : public Checker< check::PostCall,  // For intercepting allocation calls (kzalloc)
                      check::PreCall,   // For checking memcpy calls before execution
                      check::Bind       // For tracking assignments (metadata update)
                    > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Out-of-order metadata update",
                     "Flexible Array Metadata")) {}

  // Callback invoked after a call expression is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback invoked before a call expression is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback invoked when a value is bound to a memory location.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportOutOfOrderUpdate(const MemRegion *EventMR, CheckerContext &C) const;
};

/// checkPostCall: Intercepts calls to kzalloc. If the allocation appears to be
/// for an event struct (i.e. one containing the flexible array member "data"),
/// the allocated event's memory region is entered into FlexArrayUpdateMap with a
/// flag value of false (meaning the metadata update is not yet done).
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if the call is to kzalloc.
  if (!ExprHasName(OriginExpr, "kzalloc", C))
    return;

  // Retrieve the allocated event's memory region.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  // Here we assume that the allocated structure is the event struct.
  // Mark that the metadata (datalen update) has not yet been performed.
  State = State->set<FlexArrayUpdateMap>(MR, false);
  C.addTransition(State);
}

/// checkBind: Intercepts assignments (bindings). When an assignment targets a field
/// with the name "datalen", we try to identify if this is the metadata update
/// for an event struct. If so, update the corresponding FlexArrayUpdateMap entry to true.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Check if the location expression (LHS) has the name "datalen".
  if (!S)
    return;
  if (!ExprHasName(cast_or_null<Expr>(S), "datalen", C))
    return;

  // Use utility function to find the parent event struct.
  // We try to find a parent that contains the flexible array member "data".
  const Expr *ParentEvent = findSpecificTypeInParents<Expr>(cast<Expr>(S), C);
  if (!ParentEvent)
    return;

  const MemRegion *EventMR = getMemRegionFromExpr(ParentEvent, C);
  if (!EventMR)
    return;
  EventMR = EventMR->getBaseRegion();
  if (!EventMR)
    return;

  ProgramStateRef State = C.getState();
  // Mark that the metadata update (datalen assignment) has been performed.
  State = State->set<FlexArrayUpdateMap>(EventMR, true);
  C.addTransition(State);
}

/// checkPreCall: Intercepts calls to memcpy. Before the memcpy is executed,
/// if the destination points to a flexible array member "data", we check if the
/// metadata update (datalen assignment) has taken place. If not, we report a bug.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if this is a call to memcpy.
  if (!ExprHasName(OriginExpr, "memcpy", C))
    return;

  // For memcpy the destination is the first argument.
  if (Call.getNumArgs() < 1)
    return;

  // We no longer use DestVal since it is not needed.
  const Expr *DestExpr = OriginExpr->IgnoreImplicit();
  // Check whether destination expression text contains "data" (flexible array member).
  if (!ExprHasName(DestExpr, "data", C))
    return;

  // Get the parent event struct of the destination's expression.
  const Expr *ParentEvent = findSpecificTypeInParents<Expr>(DestExpr, C);
  if (!ParentEvent)
    return;

  const MemRegion *EventMR = getMemRegionFromExpr(ParentEvent, C);
  if (!EventMR)
    return;
  EventMR = EventMR->getBaseRegion();
  if (!EventMR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Updated = State->get<FlexArrayUpdateMap>(EventMR);

  // If the metadata update has not been performed, emit a bug report.
  if (Updated && *Updated == false)
    reportOutOfOrderUpdate(EventMR, C);
}

/// reportOutOfOrderUpdate: Reports a non-fatal error when a memcpy call is
/// detected on a flexible array before its metadata (datalen) update.
void SAGenTestChecker::reportOutOfOrderUpdate(const MemRegion *EventMR, CheckerContext &C) const {
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
    
  // Use the 3-argument version of the PathSensitiveBugReport (with a short and long description).
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, 
      "Out-of-order metadata update", 
      "flexible array accessed before datalen update", 
      N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects out-of-order update of metadata for flexible array members", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = 
    CLANG_ANALYZER_API_VERSION_STRING;
