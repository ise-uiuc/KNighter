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
#include "clang/AST/ExprCXX.h"

using namespace clang;
using namespace ento;
using namespace taint;

// REGISTER custom program state map to record that a pointer in dst->thread.sve_state
// was allocated from kzalloc.
// The map key is a pointer to a memory region, and the value is a bool flag.
// We will use a special sentinel key to track the fact that an allocation occurred.
REGISTER_MAP_WITH_PROGRAMSTATE(AllocMap, const MemRegion*, bool)

// We define a sentinel key to represent our "allocation recorded" flag.
// Since we cannot manufacture a MemRegion, we reuse a dummy pointer value.
static const void *SentinelKey = reinterpret_cast<const void*>(1);

namespace {

class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Wrong NULL check", "Assignment bugs")) {}

  // Callback to record in the state when an assignment to dst->thread.sve_state
  // is performed using the return value from kzalloc.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Callback to check branch conditions. We look for a NULL check on za_state
  // when we previously recorded an allocation for sve_state.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper to report the bug.
  void reportWrongNullCheck(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // We expect an assignment statement.
  if (!StoreE)
    return;

  // Attempt to cast the store statement to a BinaryOperator.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(StoreE)) {
    // Check if the left-hand side text contains "sve_state".
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    if (!LHS)
      return;

    if (!ExprHasName(LHS, "sve_state", C))
      return;

    // Now check that the right-hand side is a call to kzalloc.
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    if (!RHS)
      return;

    // Check if RHS is a call expression.
    const CallExpr *CE = dyn_cast<CallExpr>(RHS);
    if (!CE)
      return;

    // Retrieve the callee identifier from the call.
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getName() == "kzalloc") {
        // We have detected an assignment "sve_state = kzalloc(...)".
        // Record a flag in our program state using our sentinel key.
        // We ignore the actual MemRegion from LHS and instead use our dummy key.
        State = State->set<AllocMap>(reinterpret_cast<const MemRegion*>(SentinelKey), true);
        C.addTransition(State);
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition)
    return;

  // Ensure the condition is an expression.
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  // If the branch condition uses "za_state" then this might be the bug:
  // we expect the NULL check to be performed on sve_state (allocated via kzalloc)
  // but instead it uses za_state.
  if (!ExprHasName(CondExpr, "za_state", C))
    return;

  // Check whether we have recorded an allocation for sve_state.
  const bool *AllocRecorded = State->get<AllocMap>(reinterpret_cast<const MemRegion*>(SentinelKey));
  if (AllocRecorded && *AllocRecorded) {
    reportWrongNullCheck(Condition, C);
  }
}

void SAGenTestChecker::reportWrongNullCheck(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  // Create a short and clear error message:
  auto Report = std::make_unique<PathSensitiveBugReport>(
    *BT, "NULL check is performed on za_state instead of sve_state allocated by kzalloc", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects wrong NULL check: sve_state allocated by kzalloc is not checked; instead, za_state is tested", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
