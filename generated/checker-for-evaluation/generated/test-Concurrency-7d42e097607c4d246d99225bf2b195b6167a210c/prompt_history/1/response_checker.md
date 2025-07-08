```cpp
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
#include "clang/Lex/Lexer.h"  // for Lexer::getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track the freed status of reset_data.
// false means "not freed" (allocated) and true means "freed".
REGISTER_MAP_WITH_PROGRAMSTATE(ResetDataMap, const MemRegion*, bool)
// Program state map to track pointer aliasing for reset_data pointers.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

// Helper: Mark a reset_data memory region as freed in the state.
ProgramStateRef markResetDataFreed(ProgramStateRef State, const MemRegion *MR) {
  if (!MR)
    return State;
  MR = MR->getBaseRegion();
  if (!MR)
    return State;
  // Mark region as freed.
  State = State->set<ResetDataMap>(MR, true);
  
  // Also update any alias if present.
  if (const MemRegion *Alias = State->get<PtrAliasMap>(MR)) {
    Alias = Alias->getBaseRegion();
    if (Alias)
      State = State->set<ResetDataMap>(Alias, true);
  }
  return State;
}

// Helper: Register a reset_data pointer in the state (initially not freed).
ProgramStateRef registerResetData(ProgramStateRef State, const MemRegion *MR) {
  if (!MR)
    return State;
  MR = MR->getBaseRegion();
  if (!MR)
    return State;
  // If not already registered, set it as allocated (false).
  if (!State->get<ResetDataMap>(MR))
    State = State->set<ResetDataMap>(MR, false);
  return State;
}

// Helper: In checkBind, to update pointer aliasing.
ProgramStateRef updateAlias(ProgramStateRef State, const MemRegion *LHS, const MemRegion *RHS) {
  if (!LHS || !RHS)
    return State;
  LHS = LHS->getBaseRegion();
  RHS = RHS->getBaseRegion();
  if (!LHS || !RHS)
    return State;
  State = State->set<PtrAliasMap>(LHS, RHS);
  State = State->set<PtrAliasMap>(RHS, LHS);
  return State;
}

// Helper: Try to extract a CallExpr from a given statement by looking downward.
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S) {
  if (!S)
    return nullptr;
  for (const Stmt *Child : S->children()) {
    if (!Child)
      continue;
    if (const T *Casted = dyn_cast<T>(Child))
      return Casted;
    if (const T *Found = findSpecificTypeInChildren<T>(Child))
      return Found;
  }
  return nullptr;
}

class SAGenTestChecker : public Checker<check::PreCall, check::BranchCondition, check::Bind> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Use-after-free Race in reset_data",
                                         "Memory Ownership")) {}

  // checkPreCall: intercept calls to kfree and detect duplicate free.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // checkBranchCondition: intercept branch conditions that use completion_done.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

  // checkBind: track assignments including container_of uses and pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Report a bug for a duplicate free of reset_data.
  void reportRace(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Intercept calls to kfree.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Use utility function to check function name.
  if (!ExprHasName(OriginExpr, "kfree", C))
    return;

  // For kfree, usually the pointer to be freed is the first argument.
  if (Call.getNumArgs() < 1)
    return;
  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *MR = Arg0.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Consult our ResetDataMap.
  const bool *Freed = State->get<ResetDataMap>(MR);
  if (Freed && *Freed == true) {
    // Already freed: report duplicate free.
    reportRace(Call, C, MR);
    return;
  }
  // Otherwise, mark as freed.
  State = markResetDataFreed(State, MR);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition)
    return;

  // Look for branch conditions that call completion_done.
  // If the condition expression contains "completion_done", then we assume that
  // the caller has timed out and that reset_data should be freed.
  if (ExprHasName(dyn_cast<Expr>(Condition), "completion_done", C)) {
    // Attempt to locate the CallExpr for completion_done in the condition's children.
    const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(Condition);
    if (!CE)
      return;
    // Check that the call is for completion_done.
    const Expr *Origin = CE->getCallee();
    if (!Origin || !ExprHasName(Origin, "completion_done", C))
      return;
    // Assume that the first argument of completion_done is &reset_data->compl.
    if (CE->getNumArgs() < 1)
      return;
    const Expr *Arg = CE->getArg(0);
    if (!Arg)
      return;
    // Get the memory region corresponding to reset_data by stripping & and member access.
    const MemRegion *ResetMR = getMemRegionFromExpr(Arg, C);
    if (!ResetMR)
      return;
    ResetMR = ResetMR->getBaseRegion();
    if (!ResetMR)
      return;
    // Mark the reset_data as freed.
    State = markResetDataFreed(State, ResetMR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!StoreE)
    return;
  
  // If the right-hand side expression contains "container_of", we consider this a
  // creation site for reset_data. Thus, we register it in our ResetDataMap
  // as not freed.
  const Expr *StoreExpr = dyn_cast<Expr>(StoreE);
  if (StoreExpr && ExprHasName(StoreExpr, "container_of", C)) {
    const MemRegion *RHS = getMemRegionFromExpr(cast<Expr>(StoreE), C);
    if (RHS) {
      RHS = RHS->getBaseRegion();
      if (RHS)
        State = registerResetData(State, RHS);
    }
  }

  // Additionally, update pointer aliasing if both sides have memory regions.
  const MemRegion *LHS = Loc.getAsRegion();
  const MemRegion *RHS = Val.getAsRegion();
  if (LHS && RHS) {
    State = updateAlias(State, LHS, RHS);
  }
  C.addTransition(State);
}

void SAGenTestChecker::reportRace(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Race condition: reset_data double free detected", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects race condition and use-after-free due to duplicate freeing of reset_data", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```