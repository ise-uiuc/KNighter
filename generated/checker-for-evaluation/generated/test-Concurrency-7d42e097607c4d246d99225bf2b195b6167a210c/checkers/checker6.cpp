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

// Add any additional includes if needed
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states:
// Map from reset_data memory region to a bool indicating if completion_done() has been observed.
REGISTER_MAP_WITH_PROGRAMSTATE(ResetDataMap, const MemRegion *, bool)
// (Optional) Map to track pointer aliasing: if one pointer (of reset_data) is stored into another.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker< check::PreCall, check::Bind > {
  
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Race: reset_data freed twice")) {}

  // Callback that intercepts function call events before the call is executed.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback to track pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper function to report a bug.
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if the function is "completion_done"
  if (ExprHasName(OriginExpr, "completion_done", C)) {
    // We expect completion_done to be called with one argument
    if (Call.getNumArgs() < 1)
      return;
    // Extract the argument of completion_done.
    const Expr *ArgExpr = Call.getArgExpr(0);
    if (!ArgExpr)
      return;
      
    // Get the memory region corresponding to the reset_data container.
    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
      
    // Mark reset_data as "completed" (i.e., completion_done already invoked).
    State = State->set<ResetDataMap>(MR, true);
    
    // Also mark any alias if available.
    if (const MemRegion * const *Alias = State->get<PtrAliasMap>(MR))
      State = State->set<ResetDataMap>(*Alias, true);
      
    C.addTransition(State);
    return;
  }

  // Check if the function called is "kfree" (or similar free function).
  if (ExprHasName(OriginExpr, "kfree", C)) {
    // We expect kfree to have at least one argument.
    if (Call.getNumArgs() < 1)
      return;
    const Expr *ArgExpr = Call.getArgExpr(0);
    if (!ArgExpr)
      return;
      
    // Retrieve the memory region for the pointer passed to kfree.
    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
      
    // Look up the reset_data completion status.
    const bool *CompletionDone = State->get<ResetDataMap>(MR);
    // If we detect that completion_done() was already called, report a potential race.
    if (CompletionDone && *CompletionDone == true) {
      reportDoubleFree(Call, C, MR);
    }
    // Additionally, check if any alias has been marked as completed.
    if (const MemRegion * const *Alias = State->get<PtrAliasMap>(MR)) {
      const bool *AliasDone = State->get<ResetDataMap>(*Alias);
      if (AliasDone && *AliasDone == true) {
        reportDoubleFree(Call, C, *Alias);
      }
    }
    
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If the left-hand side and right-hand side correspond to memory regions, record pointer aliasing.
  const MemRegion *LHSReg = Loc.getAsRegion();
  const MemRegion *RHSReg = Val.getAsRegion();
  if (!LHSReg || !RHSReg)
    return;
    
  LHSReg = LHSReg->getBaseRegion();
  RHSReg = RHSReg->getBaseRegion();
  if (!LHSReg || !RHSReg)
    return;
  
  // Update PtrAliasMap for both regions.
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Race: reset_data freed twice", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects race condition due to improper ownership transfer of reset_data (freed twice)", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
