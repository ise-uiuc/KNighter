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
#include "clang/Lex/Lexer.h"  // Needed for Lexer::getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// ============================================================================
// 1. Customize program states
// -----------------------------------------------------------------------------
// We register a program state map "TxLockFlag" to track whether the tx lock
// (gsm->tx_lock) is acquired. We use a dummy constant key to represent the
// global lock state.
REGISTER_MAP_WITH_PROGRAMSTATE(TxLockFlag, const void*, bool)

// Define a dummy key for tx lock state.
static const void *TX_LOCK_KEY = reinterpret_cast<const void*>(0x1);

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::PreCall, check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unsynchronized Free", "Synchronization")) {}

  // Callback declarations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper function to report bug.
  void reportUnsyncFree(const CallEvent &Call, CheckerContext &C) const;
};

  
// -----------------------------------------------------------------------------
// checkPostCall: Catch the acquisition of the tx lock via the guard helper.
// We look for a call whose origin expression source text contains the string
// "guard(spinlock_irqsave)". Then we mark our global tx lock flag as true.
// -----------------------------------------------------------------------------
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Identify the lock acquisition helper call.
  if (!ExprHasName(Origin, "guard(spinlock_irqsave)", C))
    return;

  // Extract the argument representing gsm->tx_lock.
  // We assume the lock pointer is passed as the first argument.
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *LockRegion = ArgVal.getAsRegion();
  if (!LockRegion)
    return;
  LockRegion = LockRegion->getBaseRegion();

  // For simplicity, we use a global flag: update our TxLockFlag state.
  ProgramStateRef State = C.getState();
  State = State->set<TxLockFlag>(TX_LOCK_KEY, true);
  C.addTransition(State);
}


// -----------------------------------------------------------------------------
// checkPreCall: Intercept calls to kfree and check whether tx queues are freed
// unsafely. We use ExprHasName to check if the argument string contains either
// "tx_ctrl_list" or "tx_data_list". If so, verify that the tx lock is acquired.
// -----------------------------------------------------------------------------
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Only examine calls to kfree.
  if (!ExprHasName(Origin, "kfree", C))
    return;

  // Check the first argument passed to kfree.
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;
  
  // Look for tx queue names in the source text.
  bool isTxQueue = ExprHasName(ArgExpr, "tx_ctrl_list", C) ||
                   ExprHasName(ArgExpr, "tx_data_list", C);
  if (!isTxQueue)
    return;

  // Retrieve global tx lock flag.
  ProgramStateRef State = C.getState();
  const bool *Locked = State->get<TxLockFlag>(TX_LOCK_KEY);
  if (!Locked || !(*Locked)) {
    // Report unsynchronized free if tx lock is not acquired.
    reportUnsyncFree(Call, C);
  }
}


// -----------------------------------------------------------------------------
// checkBind: Use checkBind to propagate pointer aliasing information if needed.
// In this simple checker, we do not modify state but could extend to update a
// PtrAliasMap if necessary.
// -----------------------------------------------------------------------------
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // For this checker, we do not propagate aliasing,
  // but one could update a PtrAliasMap here if desired.
  // Simply add a transition with the current state.
  C.addTransition(C.getState());
}


// -----------------------------------------------------------------------------
// reportUnsyncFree: Report a bug via a non-fatal error node.
// -----------------------------------------------------------------------------
void SAGenTestChecker::reportUnsyncFree(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing tx queue without acquiring tx_lock", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detect unsynchronized freeing of tx queues without holding tx_lock", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
