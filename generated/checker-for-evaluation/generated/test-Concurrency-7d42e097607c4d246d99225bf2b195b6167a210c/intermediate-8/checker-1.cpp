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

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states.
//
// FreedStateMap: maps a MemRegion (reset_data structure) to a boolean value
// indicating if it has been freed (true means freed).
REGISTER_MAP_WITH_PROGRAMSTATE(FreedStateMap, const MemRegion *, bool)
// PtrAliasMap: maps a pointer's MemRegion to its canonical region (for alias propagation).
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::BranchCondition, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Race condition in reset_data free")) {}

  // Callback declarations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper to report a double free race.
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C, const MemRegion *R) const;
  
  // Helper to resolve canonical region using PtrAliasMap.
  const MemRegion* resolveCanonicalRegion(const MemRegion *Reg, ProgramStateRef State) const {
    // State->get returns a pointer-to the value stored in the map.
    const MemRegion *const *CanonPtr = State->get<PtrAliasMap>(Reg);
    if (CanonPtr)
      return *CanonPtr;
    return Reg;
  }
};

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C, const MemRegion *R) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Race condition: reset_data double free detected", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // We intercept calls to 'kfree'.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use ExprHasName for reliable checking.
  if (!ExprHasName(OriginExpr, "kfree", C))
    return;
  
  ProgramStateRef State = C.getState();
  // For kfree, typically the pointer to free is the first argument.
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Resolve canonical region via alias mapping.
  const MemRegion *CanonMR = resolveCanonicalRegion(MR, State);
  // Check if this region has already been freed.
  const bool *AlreadyFreed = State->get<FreedStateMap>(CanonMR);
  if (AlreadyFreed && *AlreadyFreed == true) {
    reportDoubleFree(Call, C, CanonMR);
    return;
  }
  
  // Mark the region as freed.
  State = State->set<FreedStateMap>(CanonMR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition)
    return;
  
  // We check if the condition contains the text "completion_done"
  // using the utility function ExprHasName.
  if (ExprHasName(dyn_cast<Expr>(Condition), "completion_done", C)) {
    // Look down the AST to find the CallExpr of completion_done.
    const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(Condition);
    if (!CE)
      return;
    
    // We assume the first argument of completion_done is the pointer we want.
    if (CE->getNumArgs() < 1)
      return;
      
    const Expr *Arg = CE->getArg(0);
    if (!Arg)
      return;
      
    // Get the MemRegion corresponding to the argument.
    const MemRegion *MR = getMemRegionFromExpr(Arg, C);
    if (!MR)
      return;
      
    MR = MR->getBaseRegion();
    if (!MR)
      return;
      
    // Resolve canonical region.
    const MemRegion *CanonMR = resolveCanonicalRegion(MR, State);
    // Mark this region as "freed" (or safe to free) so that later free calls
    // from other paths can be detected as a potential race/double free.
    State = State->set<FreedStateMap>(CanonMR, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // When binding a pointer to another, propagate alias.
  const MemRegion *LHSReg = Loc.getAsRegion();
  const MemRegion *RHSReg = Val.getAsRegion();
  if (!LHSReg || !RHSReg)
    return;
  
  LHSReg = LHSReg->getBaseRegion();
  RHSReg = RHSReg->getBaseRegion();
  if (!LHSReg || !RHSReg)
    return;
  
  // Record aliasing in both directions.
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects a race condition when freeing reset_data due to unsynchronized free paths",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
