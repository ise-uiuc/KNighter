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
#include "clang/Lex/Lexer.h"  // for getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: a map to track if an exec_queue's xef field has been initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(InitializedXefMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker 
  : public Checker<check::Bind, check::PostCall> { 
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Premature Publication of exec_queue", "Use-after-free")) {}

  // Callback for field binding: track initialization of the xef field.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Callback for post-call: detect if xa_alloc publishes an exec_queue before its xef field is initialized.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportPrematurePublication(const MemRegion *MR, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check if the binding is part of an assignment to a field.
  // We inspect the source text of the whole store statement to see if it involves "->xef".
  if (!StoreE)
    return;
    
  if (!ExprHasName(dyn_cast<Expr>(StoreE), "->xef", C))
    return;

  // Further, check if the right-hand side is a call to "xe_file_get"
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(StoreE)) {
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    const CallExpr *CallRHS = dyn_cast<CallExpr>(RHS);
    if (!CallRHS)
      return;
    // Use the appropriate API for CallExpr to get the callee expression.
    const Expr *Origin = CallRHS->getCallee();
    if (!Origin || !ExprHasName(Origin, "xe_file_get", C))
      return;
  } else {
    // In some cases the binding might not be a binary operator;
    // check the entire statement text.
    if (!ExprHasName(dyn_cast<Expr>(StoreE), "xe_file_get", C))
      return;
  }

  // At this point, we have detected an assignment of the form "q->xef = xe_file_get(...)".
  // Retrieve the MemRegion corresponding to the left-hand side (container object's region).
  const MemRegion *MR = getMemRegionFromExpr(dyn_cast<Expr>(StoreE), C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark the region as having been initialized.
  State = State->set<InitializedXefMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Use the utility function to check if this call is to "xa_alloc"
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin || !ExprHasName(Origin, "xa_alloc", C))
    return;

  // xa_alloc's third argument (index 2) carries the published exec_queue pointer.
  if (Call.getNumArgs() < 3)
    return;
  
  SVal Arg2 = Call.getArgSVal(2);
  const MemRegion *MR = Arg2.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Lookup in our program state whether this exec_queue (its container region) 
  // had its 'xef' field initialized.
  const bool *Initialized = State->get<InitializedXefMap>(MR);
  if (!Initialized || !(*Initialized)) {
    // Report bug: the exec_queue is published without proper initialization.
    reportPrematurePublication(MR, C);
  }
}

void SAGenTestChecker::reportPrematurePublication(const MemRegion *MR, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "exec_queue published with uninitialized 'xef' field", N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects premature publication of an exec_queue object (xa_alloc called before q->xef is initialized)", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
