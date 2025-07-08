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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track allocations that come from kzalloc.
// The key is the memregion corresponding to the destination (e.g. dst->thread.sve_state)
// and the value is a flag (true) to denote that a kzalloc allocation was performed.
REGISTER_MAP_WITH_PROGRAMSTATE(KzallocMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker< check::Bind, check::BranchCondition > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Incorrect NULL check on pointer after kzalloc allocation")) {}

  // Callback for tracking pointer assignments.
  // We intercept assignments of the form:
  //   dst->thread.sve_state = kzalloc(...);
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Callback for checking branch conditions.
  // We intercept a condition that tests the wrong pointer field: "thread.za_state"
  // instead of "thread.sve_state" after a kzalloc allocation.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

// In checkBind, we inspect the binding statement. If the RHS is a call to kzalloc,
// then we record the LHS memory region (i.e. pointer) as having been allocated
// by kzalloc in our KzallocMap.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  // Always use the base region.
  LHSReg = LHSReg->getBaseRegion();

  // Look downward in the binding statement to see if a call expression is present.
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(StoreE);
  if (!CE)
    return;

  // Check if the call expression corresponds to a kzalloc call.
  // Use the utility function ExprHasName on the call expression to verify this.
  const Expr *OriginExpr = CE;
  if (!ExprHasName(OriginExpr, "kzalloc", C))
    return;

  // Record in our program state that LHSReg was allocated via kzalloc.
  State = State->set<KzallocMap>(LHSReg, true);
  C.addTransition(State);
}

// In checkBranchCondition, we analyze the condition expression. We look for
// an incorrect NULL check on the wrong thread field by checking if the source
// text of the condition contains "thread.za_state". If detected, we report a bug.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // We assume the condition is an expression.
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  // If the condition's source text contains "thread.za_state", it is likely that
  // the programmer erroneously checked the wrong pointer (should check thread.sve_state).
  if (ExprHasName(CondExpr, "thread.za_state", C)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Incorrect NULL check: checking dst->thread.za_state instead of dst->thread.sve_state after kzalloc", N);
    C.emitReport(std::move(report));
  }
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects an incorrect NULL check on a pointer allocated via kzalloc (checks the wrong field)", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
