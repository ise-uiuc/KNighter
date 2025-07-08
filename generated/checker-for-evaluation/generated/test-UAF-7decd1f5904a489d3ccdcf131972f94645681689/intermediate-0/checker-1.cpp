#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
// Removed: #include "clang/Lexer/Lexer.h" since it does not exist in Clang-18.
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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to record if a subflow object (its MemRegion)
// has been freed via mptcp_close_ssk.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedSubflowMap, const MemRegion*, bool)

// Optional: if pointer aliasing needs to be tracked, one can add:
// REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall, check::Location, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Use-after-free: Freed subflow access")) {}

  // Called right after a function call is processed.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Called when a memory location is accessed (load/store).
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

  // Track pointer aliasing (optional) to propagate "freed" status.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Report a use-after-free bug.
  void reportUAF(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Check if the call is to mptcp_close_ssk.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "mptcp_close_ssk", C))
    return;

  // For mptcp_close_ssk, the subflow pointer is passed as the 3rd argument (index 2).
  if (Call.getNumArgs() < 3)
    return;
  SVal SubflowArgVal = Call.getArgSVal(2);
  const MemRegion *MR = SubflowArgVal.getAsRegion();
  if (!MR)
    return;

  // Obtain the base region per our guidelines.
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  // Mark this subflow region as freed.
  State = State->set<FreedSubflowMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // We are interested only in load accesses (reading fields).
  if (!IsLoad)
    return;
  
  // Use utility function to check if the field name "request_join" is present in the source.
  if (!ExprHasName(dyn_cast<Expr>(S), "request_join", C))
    return;
  
  // Get the memory region from the accessed location.
  const MemRegion *MR = getMemRegionFromExpr(S, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Freed = State->get<FreedSubflowMap>(MR);
  if (Freed && *Freed) {
    reportUAF(S, C);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHS = Loc.getAsRegion();
  const MemRegion *RHS = Val.getAsRegion();

  if (!LHS || !RHS)
    return;

  // Get the base regions.
  LHS = LHS->getBaseRegion();
  RHS = RHS->getBaseRegion();
  if (!LHS || !RHS)
    return;

  // (Optional) Propagate aliasing: if one of the regions was marked as freed,
  // mark its alias also as freed.
  bool LHSFreed = false, RHSFreed = false;
  if (const bool *Flag = State->get<FreedSubflowMap>(LHS))
    LHSFreed = *Flag;
  if (const bool *Flag = State->get<FreedSubflowMap>(RHS))
    RHSFreed = *Flag;
  
  if (LHSFreed && !RHSFreed) {
    State = State->set<FreedSubflowMap>(RHS, true);
    C.addTransition(State);
  } else if (RHSFreed && !LHSFreed) {
    State = State->set<FreedSubflowMap>(LHS, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportUAF(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "UAF: Accessing field 'request_join' of a freed subflow", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free: accessing subflow->request_join after the subflow is freed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
