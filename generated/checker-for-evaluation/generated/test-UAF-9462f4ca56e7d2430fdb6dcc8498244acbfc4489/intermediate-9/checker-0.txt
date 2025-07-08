#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
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

// You may add additional includes below if needed.
  
using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track the state of the lock.
// The map associates a lock's MemRegion (e.g. gsm->tx_lock) with a boolean flag
// indicating whether the lock is held (true means held).
REGISTER_MAP_WITH_PROGRAMSTATE(LockStateMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;
public:
   SAGenTestChecker() : BT(new BugType(this, "Unsynchronized Free")) {}

   // Callback to intercept function call events.
   void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
   // (Optional) You could declare helper functions here if needed.
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
   ProgramStateRef State = C.getState();
   const Expr *OriginExpr = Call.getOriginExpr();
   if (!OriginExpr)
      return;

   // --- 1. Detect lock acquisition calls ---
   // Look for function calls whose source text contains "guard" or "spin_lock".
   if (ExprHasName(OriginExpr, "guard", C) || ExprHasName(OriginExpr, "spin_lock", C)) {
      // Assume that the first argument is the lock object.
      if (Call.getNumArgs() > 0) {
         SVal LockVal = Call.getArgSVal(0);
         const MemRegion *LockRegion = LockVal.getAsRegion();
         if (LockRegion) {
            LockRegion = LockRegion->getBaseRegion();
            // Mark the lock as held (true) in our LockStateMap.
            State = State->set<LockStateMap>(LockRegion, true);
            C.addTransition(State);
            // No further processing for lock acquisition.
            return;
         }
      }
   }

   // --- 2. Detect calls to kfree on shared list items ---
   // We look for calls where the callee's source text contains "kfree".
   if (ExprHasName(OriginExpr, "kfree", C)) {
      // Check the argument to kfree.
      if (Call.getNumArgs() > 0) {
         const Expr *ArgExpr = Call.getArgExpr(0);
         if (ArgExpr &&
             // Check whether the argument's source text indicates that it belongs
             // to a shared list such as "tx_ctrl_list" or "tx_data_list".
             (ExprHasName(ArgExpr, "tx_ctrl_list", C) || ExprHasName(ArgExpr, "tx_data_list", C))) {

            // Try to infer the corresponding lock region.
            // As a heuristic, scan upward in the AST from the argument to see if any
            // expression contains "tx_lock". If found, treat that as the lock object.
            const Expr *LockExpr = findSpecificTypeInParents<Expr>(ArgExpr, C);
            if (LockExpr && ExprHasName(LockExpr, "tx_lock", C)) {
               const MemRegion *LockRegion = getMemRegionFromExpr(LockExpr, C);
               if (LockRegion) {
                  LockRegion = LockRegion->getBaseRegion();
                  // Check our current program state to see if the lock is held.
                  const bool *IsHeld = State->get<LockStateMap>(LockRegion);
                  if (!IsHeld || !(*IsHeld)) {
                     // Lock is not held. Report an unsynchronized free.
                     ExplodedNode *N = C.generateNonFatalErrorNode();
                     if (!N)
                        return;
                     auto Report = std::make_unique<PathSensitiveBugReport>(
                         *BT, "Unsynchronized free of shared list", N);
                     C.emitReport(std::move(Report));
                  }
               }
            } else {
               // If we cannot infer the lock, report as a potential bug conservatively.
               ExplodedNode *N = C.generateNonFatalErrorNode();
               if (!N)
                  return;
               auto Report = std::make_unique<PathSensitiveBugReport>(
                   *BT, "Unsynchronized free of shared list", N);
               C.emitReport(std::move(Report));
            }
         }
      }
   }

   C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
   registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unsynchronized free of shared list in gsm_cleanup_mux", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
