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
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map that maps a memory region (structure variable)
// to a bool flag that indicates if the region has been fully zeroed.
REGISTER_MAP_WITH_PROGRAMSTATE(InitRegionMap, const MemRegion *, bool)
// Register a program state map to track aliasing relationships between regions.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  // The bug type message is short and clear.
  SAGenTestChecker() : BT(new BugType(this, "Structure not zeroed", "Security")) {}

  // Callback to intercept function calls before they are evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to intercept function calls after they are evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to track assignments (pointer bindings) for alias propagation.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Report a potential info leak when an uninitialized structure is used.
  void reportInfoLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const;
  
  // Helper to mark a memory region (and its alias if present) as initialized.
  ProgramStateRef setInitialized(ProgramStateRef State, const MemRegion *MR) const;
};

ProgramStateRef SAGenTestChecker::setInitialized(ProgramStateRef State, const MemRegion *MR) const {
  if (!MR)
    return State;
  MR = MR->getBaseRegion();
  if (!MR)
    return State;
  State = State->set<InitRegionMap>(MR, true);
  
  // Also mark any tracked alias as initialized.
  if (const MemRegion* const *AliasPtr = State->get<PtrAliasMap>(MR)) {
    const MemRegion *Alias = *AliasPtr;
    if (Alias) {
      Alias = Alias->getBaseRegion();
      if (Alias)
        State = State->set<InitRegionMap>(Alias, true);
    }
  }
  return State;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept calls to memset.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Use utility function to check function name.
  if (!ExprHasName(OriginExpr, "memset", C))
    return;

  // For memset, check the second argument is 0.
  // memset(void *s, int c, size_t n)
  const Expr *SecondArg = dyn_cast<Expr>(Call.getArgExpr(1));
  if (!SecondArg)
    return;
  llvm::APSInt Val;
  if (!EvaluateExprToInt(Val, SecondArg, C))
    return;
  if (Val != 0)
    return;

  // Get destination memory region from the first argument.
  const Expr *DestExpr = dyn_cast<Expr>(Call.getArgExpr(0));
  if (!DestExpr)
    return;
  const MemRegion *MR = getMemRegionFromExpr(DestExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = setInitialized(State, MR);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // Track aliasing: when a structure pointer is assigned to another,
  // update the PtrAliasMap.
  ProgramStateRef State = C.getState();
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  if (!LHS)
    return;
  const MemRegion *RHS = Val.getAsRegion();
  if (!RHS)
    return;
  RHS = RHS->getBaseRegion();
  if (!RHS)
    return;

  State = State->set<PtrAliasMap>(LHS, RHS);
  State = State->set<PtrAliasMap>(RHS, LHS);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept calls to user-copy functions that copy structure data.
  // We are interested in calls such as "nla_put" or "nla_put_64bit" which are used
  // to copy a structure (e.g., tc_skbmod) to user space.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  bool IsUserCopy = false;
  // Check if the call is to a known user-copying helper.
  if (ExprHasName(OriginExpr, "nla_put", C))
    IsUserCopy = true;
  else if (ExprHasName(OriginExpr, "nla_put_64bit", C))
    IsUserCopy = true;

  if (!IsUserCopy)
    return;

  ProgramStateRef State = C.getState();
  // Assume that the pointer to the structure is passed as the fourth argument (index 3)
  if (Call.getNumArgs() <= 3)
    return;
  SVal ArgVal = Call.getArgSVal(3);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const bool *Initialized = State->get<InitRegionMap>(MR);
  // If the region is marked as initialized (zeroed by memset), nothing to report.
  if (Initialized && *Initialized)
    return;

  // Region is not marked as fully initialized; emit a bug report.
  reportInfoLeak(Call, C, MR);
}

void SAGenTestChecker::reportInfoLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Structure not fully zeroed before user copy – potential information leak", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects uninitialized (partially zeroed) structures being copied to user space, which may leak kernel information", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
