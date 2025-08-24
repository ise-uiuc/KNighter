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
#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track whether gsm->tx_lock is currently held.
REGISTER_TRAIT_WITH_PROGRAMSTATE(TxLockHeld, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        check::BeginFunction,
        check::EndFunction,
        check::PreCall,
        check::PostCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Missing tx_lock on list free", "Concurrency")) {}

      void checkBeginFunction(CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static bool callNameIs(const CallEvent &Call, CheckerContext &C, StringRef Name);
      static bool isFreeLike(const CallEvent &Call, CheckerContext &C);
      static bool argIsTxLock(const CallEvent &Call, unsigned ArgIdx, CheckerContext &C);
      static bool exprContainsTxList(const Stmt *S, CheckerContext &C);
      static bool forIteratesTxLists(const ForStmt *F, CheckerContext &C);
};

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // At function entry, we assume tx_lock is not held.
  State = State->set<TxLockHeld>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Defensively reset; analysis engine will discard state anyway at function end.
  ProgramStateRef State = C.getState();
  State = State->set<TxLockHeld>(false);
  C.addTransition(State);
}

bool SAGenTestChecker::callNameIs(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

bool SAGenTestChecker::argIsTxLock(const CallEvent &Call, unsigned ArgIdx, CheckerContext &C) {
  if (ArgIdx >= Call.getNumArgs())
    return false;
  const Expr *ArgE = Call.getArgExpr(ArgIdx);
  if (!ArgE)
    return false;
  // Match textual usage of the designated lock
  return ExprHasName(ArgE, "tx_lock", C);
}

bool SAGenTestChecker::isFreeLike(const CallEvent &Call, CheckerContext &C) {
  // We consider kfree/kvfree/vfree as free-like in kernel code.
  return callNameIs(Call, C, "kfree") ||
         callNameIs(Call, C, "kvfree") ||
         callNameIs(Call, C, "vfree");
}

bool SAGenTestChecker::exprContainsTxList(const Stmt *S, CheckerContext &C) {
  if (!S)
    return false;

  if (const auto *E = dyn_cast<Expr>(S)) {
    if (ExprHasName(E, "tx_ctrl_list", C))
      return true;
    if (ExprHasName(E, "tx_data_list", C))
      return true;
  }

  // Fallback: try to find a MemberExpr among children and check its text.
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    const Expr *MEE = dyn_cast<Expr>(const_cast<MemberExpr*>(ME));
    if (MEE) {
      if (ExprHasName(MEE, "tx_ctrl_list", C))
        return true;
      if (ExprHasName(MEE, "tx_data_list", C))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::forIteratesTxLists(const ForStmt *F, CheckerContext &C) {
  if (!F)
    return false;

  // list_for_each_entry_safe expands to a for-loop where the condition
  // typically compares against the 'head' which will reference &gsm->tx_*_list.
  if (exprContainsTxList(F->getInit(), C))
    return true;
  if (exprContainsTxList(F->getCond(), C))
    return true;
  if (exprContainsTxList(F->getInc(), C))
    return true;

  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect spin_lock* acquisitions on gsm->tx_lock
  if (callNameIs(Call, C, "spin_lock") ||
      callNameIs(Call, C, "spin_lock_irqsave") ||
      callNameIs(Call, C, "spin_lock_bh") ||
      callNameIs(Call, C, "spin_lock_irq")) {
    if (argIsTxLock(Call, 0, C)) {
      State = State->set<TxLockHeld>(true);
      C.addTransition(State);
      return;
    }
  }

  // Detect spin_unlock* releases on gsm->tx_lock
  if (callNameIs(Call, C, "spin_unlock") ||
      callNameIs(Call, C, "spin_unlock_irqrestore") ||
      callNameIs(Call, C, "spin_unlock_bh") ||
      callNameIs(Call, C, "spin_unlock_irq")) {
    if (argIsTxLock(Call, 0, C)) {
      State = State->set<TxLockHeld>(false);
      C.addTransition(State);
      return;
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeLike(Call, C))
    return;

  const Stmt *S = Call.getOriginExpr();
  if (!S)
    return;

  // Ensure this kfree/kvfree/vfree is inside a list_for_each_entry_safe over tx_*_list
  const ForStmt *EnclosingFor = findSpecificTypeInParents<ForStmt>(S, C);
  if (!EnclosingFor)
    return;

  if (!forIteratesTxLists(EnclosingFor, C))
    return;

  ProgramStateRef State = C.getState();
  bool Held = State->get<TxLockHeld>();
  if (Held)
    return;

  // Report: free of tx_*_list node without holding tx_lock
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing tx_*_list entries without holding tx_lock (possible UAF).", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing tx_*_list entries without holding gsm->tx_lock in loops",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
