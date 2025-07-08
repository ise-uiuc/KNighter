```cpp
#include "clang/AST/ASTContext.h"
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

// Customize program states
REGISTER_MAP_WITH_PROGRAMSTATE(ResetDataStateMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "ResetData Race", "Race Condition")) {}

  // Callback Functions Declaration
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Self-defined helper: Report double free on reset_data
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                          const MemRegion *MR) const;
};

// Helper: report double-free error
void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                                          const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<BasicBugReport>(
      *BT, "ResetData race: reset_data structure is freed in multiple contexts", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

// checkPostCall: Intercept calls to free functions (e.g., kfree) and check for double free
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the utility function ExprHasName for accurate checking.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "kfree", C))
    return;

  // Expect the pointer to be freed is the first argument
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  ProgramStateRef State = C.getState();
  const bool *AlreadyFreed = State->get<ResetDataStateMap>(MR);
  if (AlreadyFreed && *AlreadyFreed) {
    reportDoubleFree(Call, C, MR);
    return;
  }
  
  // Mark this reset_data region as freed
  State = State->set<ResetDataStateMap>(MR, true);
  // Propagate the freed state to any alias of MR
  if (const MemRegion *Alias = State->get<PtrAliasMap>(MR))
    State = State->set<ResetDataStateMap>(Alias->getBaseRegion(), true);
  
  C.addTransition(State);
}

// checkBind: Track pointer aliasing for reset_data pointer
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();

  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();

  // Record aliasing information in both directions
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  
  C.addTransition(State);
}

// checkBranchCondition: Intercept branch conditions that call completion_done()
// and mark the associated reset_data as freed
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition)
    return;
  
  // Check if the source text of the condition contains "completion_done"
  if (!ExprHasName(dyn_cast<Expr>(Condition), "completion_done", C))
    return;
  
  // Find a call expression within the condition
  const CallExpr *CallE = findSpecificTypeInChildren<CallExpr>(Condition);
  if (!CallE)
    return;
  
  // Verify that the call is to completion_done
  if (!ExprHasName(CallE, "completion_done", C))
    return;
  
  // Retrieve the argument to completion_done (expected at index 0)
  if (CallE->getNumArgs() < 1)
    return;
  const Expr *ArgExpr = CallE->getArg(0);
  if (!ArgExpr)
    return;
  
  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  
  // Mark the reset_data region as freed because the caller has timed out.
  const bool *Freed = State->get<ResetDataStateMap>(MR);
  if (!Freed || !*Freed) {
    State = State->set<ResetDataStateMap>(MR, true);
    if (const MemRegion *Alias = State->get<PtrAliasMap>(MR))
      State = State->set<ResetDataStateMap>(Alias->getBaseRegion(), true);
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects race conditions in reset_data lifecycle management (double free of reset_data)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```