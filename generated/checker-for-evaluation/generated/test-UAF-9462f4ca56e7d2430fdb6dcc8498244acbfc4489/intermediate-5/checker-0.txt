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
#include "clang/Lex/Lexer.h"  // needed for Lexer::getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states:
// We use a map from a unique key (here a const void* we define) to a bool indicating whether gsm->tx_lock is held.
REGISTER_MAP_WITH_PROGRAMSTATE(LockStateMap, const void*, bool)

// Define a unique key for our tx_lock.
// We choose a constant pointer value that uniquely represents gsm->tx_lock.
static const void *TxLockKey = (const void *)"gsm_tx_lock";

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Unsynchronized free", "Locking errors")) {}

  // Callback function: checkPostCall is used to track lock acquisition and release.
  // We look for calls that acquire or release the critical lock (gsm->tx_lock).
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback function: checkPreCall intercepts calls to free functions.
  // We check if free is being called on shared list memory (tx_ctrl_list or tx_data_list)
  // while gsm->tx_lock is not held.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use ExprHasName to check for locking/unlocking functions.
  // Check for lock acquisition: functions that lock the tx_lock.
  // We support "spin_lock_irqsave" and also a guard-like call that contains "lock" in its text.
  if ((ExprHasName(OriginExpr, "spin_lock_irqsave", C) ||
       ExprHasName(OriginExpr, "guard", C)) &&
      ExprHasName(OriginExpr, "tx_lock", C)) {
    // Mark the tx_lock as acquired.
    State = State->set<LockStateMap>(TxLockKey, true);
    C.addTransition(State);
    return;
  }

  // Check for lock release: e.g. "spin_unlock" functions that mention tx_lock.
  if (ExprHasName(OriginExpr, "spin_unlock", C) &&
      ExprHasName(OriginExpr, "tx_lock", C)) {
    // Mark the tx_lock as released.
    State = State->set<LockStateMap>(TxLockKey, false);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // We are interested in free calls.
  // Use ExprHasName on the origin expression to reliably check if this is a 'kfree' call.
  if (!ExprHasName(OriginExpr, "kfree", C))
    return;
  
  // Now, we look at the free's argument.
  // In the buggy code, free is invoked on entries of tx_ctrl_list and tx_data_list.
  // We use ExprHasName on the free call's origin expression to check if the pointer
  // being freed is associated with "tx_ctrl_list" or "tx_data_list".
  // (The source text of the free call should contain one of these names.)
  if (!(ExprHasName(OriginExpr, "tx_ctrl_list", C) || 
        ExprHasName(OriginExpr, "tx_data_list", C)))
    return;
  
  // Check the current lock state.
  bool IsLocked = false;
  if (const bool *Val = State->get<LockStateMap>(TxLockKey))
    IsLocked = *Val;
  
  // If the lock is not held at this point, report a potential use-after-free bug.
  if (!IsLocked) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Unsynchronized free of shared tx_list in cleanup", N);
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsynchronized free of shared tx lists in cleanup (missing gsm->tx_lock)", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
