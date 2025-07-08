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

// We use a program state map to record if a kzalloc call allocated the correct field.
// Keyed by the current function's location context.
REGISTER_MAP_WITH_PROGRAMSTATE(KzallocAllocMap, const LocationContext*, bool)

namespace {

class SAGenTestChecker 
    : public Checker<check::PostCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Allocation NULL Check Mismatch")) {}

  // We intercept call events after a call is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // We intercept branch condition evaluation.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Report a bug when detecting that a null-check is performed on the wrong pointer.
  void reportMismatch(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Check if the call is to kzalloc.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use ExprHasName to check the callee in a robust manner.
  if (!ExprHasName(OriginExpr, "kzalloc", C))
    return;

  // We now try to find if this kzalloc call is assigned to thread.sve_state.
  // Go upward in the AST tree to find an assignment operation.
  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(OriginExpr, C);
  if (!BO || !BO->isAssignmentOp())
    return;

  // Check if the left-hand side of the assignment has the name "thread.sve_state".
  const Expr *LHS = BO->getLHS()->IgnoreImplicit();
  if (LHS && ExprHasName(LHS, "thread.sve_state", C)) {
    // Record in the program state that a kzalloc call allocated thread.sve_state.
    ProgramStateRef State = C.getState();
    const LocationContext *LCtx = C.getLocationContext();
    State = State->set<KzallocAllocMap>(LCtx, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // We only care about branch conditions (e.g., if, while).
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  // Check if the condition source text mentions "thread.za_state".
  // This indicates a null-check is being made on the wrong field.
  if (!ExprHasName(CondExpr, "thread.za_state", C))
    return;

  // Retrieve the state flag from the current function context.
  const LocationContext *LCtx = C.getLocationContext();
  const bool *AllocFlag = State->get<KzallocAllocMap>(LCtx);
  if (AllocFlag && *AllocFlag) {
    // We have previously recorded a kzalloc call for thread.sve_state,
    // yet here a null-check is performed on thread.za_state.
    reportMismatch(Condition, C);
  }
}

void SAGenTestChecker::reportMismatch(const Stmt *Condition, CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Incorrect NULL check: memory was allocated to thread.sve_state but "
           "the NULL check is performed on thread.za_state", ErrNode);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects mismatched NULL check for kzalloc call on thread.sve_state", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
