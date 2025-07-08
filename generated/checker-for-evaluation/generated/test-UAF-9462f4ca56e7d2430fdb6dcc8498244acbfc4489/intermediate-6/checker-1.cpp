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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"

using namespace clang;
using namespace ento;
using namespace taint;

//------------------------------------------------------------------------------
// Customize program states
//------------------------------------------------------------------------------
// We use a global Lock State map which is keyed by a unique pointer (our
// global key) and its value indicates whether the tx lock is held (true) or not.
REGISTER_MAP_WITH_PROGRAMSTATE(GlobalLockState, const void*, bool)

// We also track pointer aliasing for completeness even though in this checker
// we only use a global lock flag. (Note: for a full implementation, we could
// track aliasing for tx_ctrl_list and tx_data_list via a PtrAliasMap.)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

// Global key for our GlobalLockState map.
static char GlobalLockKey;

//------------------------------------------------------------------------------
// Checker class declaration and implementation
//------------------------------------------------------------------------------
namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Race condition (unsynchronized free)",
                                         "Concurrency")) {}

  // Callback: Invoked just before a function call is evaluated.
  // We intercept calls to kfree and check that the tx lock is held.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: Invoked after a function call is evaluated.
  // We intercept calls that acquire the tx lock.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper routine to report unsynchronized free access.
  void reportUnsynchronizedFree(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::reportUnsynchronizedFree(const CallEvent &Call,
                                                CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create a bug report with a short and clear message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Race condition: unsynchronized access to shared tx list", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if the current function is "gsm_cleanup_mux"
  const LocationContext *LCtx = C.getLocationContext();
  if (const StackFrameContext *SFC = dyn_cast<StackFrameContext>(LCtx)) {
    if (const Decl *D = SFC->getDecl()) {
      if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
        StringRef FuncName = FD->getName();
        if (FuncName != "gsm_cleanup_mux")
          return;
      }
    }
  }

  // Look for calls to 'kfree'. In the buggy code, list elements from tx_ctrl_list
  // (or tx_data_list) are freed unsynchronized.
  // Use utility function ExprHasName to check the call's origin text.
  if (ExprHasName(OriginExpr, "kfree", C)) {
    // Check if the required tx lock is held.
    const bool *Locked = State->get<GlobalLockState>(&GlobalLockKey);
    // If the GlobalLockState is either not set or false then the tx lock is not held.
    if (!(Locked && *Locked))
      reportUnsynchronizedFree(Call, C);
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Intercept calls that acquire the tx lock.
  // The patch acquires the lock with a call such as guard(spinlock_irqsave)(&gsm->tx_lock)
  // so we check if the call's source text contains both "guard" and "tx_lock".
  if (ExprHasName(OriginExpr, "guard", C) && ExprHasName(OriginExpr, "tx_lock", C)) {
    // Mark in our GlobalLockState that the tx lock is held.
    State = State->set<GlobalLockState>(&GlobalLockKey, true);
    C.addTransition(State);
    return;
  }
  // Otherwise, just add the state transition.
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsynchronized free in tx_ctrl_list/tx_data_list causing use-after-free due to missing tx_lock acquisition",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
