#include "clang/AST/Expr.h"
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

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state:
// We use a map from MemRegion* to bool to record a pending allocation. Because we do not have
// iteration support, we choose to record a dummy key for the case of a pending allocation into
// the sve_state field.
REGISTER_MAP_WITH_PROGRAMSTATE(AllocMap, const MemRegion*, bool)

// We choose a unique key (dummy pointer value) to represent that a kzalloc call was assigned to sve_state.
static const MemRegion *PendingSveKey = reinterpret_cast<const MemRegion *>(0x1);

namespace {

/// SAGenTestChecker detects a mismatched null-check: the allocation is done
/// into the sve_state field via kzalloc but later a null-check is performed on a field
/// (za_state) that is not the allocated one.
class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> { 
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Mismatched null-check in memory allocation")) {}

  // Callback: Called when a value is bound to a memory region.
  // We check for assignments into the sve_state field that use kzalloc.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  
  // Callback: Called when evaluating a branch condition.
  // We look for a null-check that erroneously tests za_state instead of sve_state.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // Make sure we have a valid statement.
  if (!StoreE)
    return;
  
  // We want to track assignments to the sve_state field.
  // Use utility function ExprHasName on the entire assignment expression.
  const Expr *StoreExpr = dyn_cast<Expr>(StoreE);
  if (!StoreExpr)
    return;
  
  // If the source text of the assignment does not mention "sve_state", ignore.
  if (!ExprHasName(StoreExpr, "sve_state", C))
    return;
  
  // Next, check if the same statement contains a call to kzalloc.
  if (!ExprHasName(StoreExpr, "kzalloc", C))
    return;
  
  // We have an assignment into sve_state with a kzalloc call.
  // Mark in our ProgramState that there is a pending allocation for sve_state that
  // has not been null-checked.
  ProgramStateRef State = C.getState();
  State = State->set<AllocMap>(PendingSveKey, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;
  
  // Cast Condition to an Expr since ExprHasName expects an Expr pointer.
  const Expr *ConditionExpr = dyn_cast<Expr>(Condition);
  if (!ConditionExpr)
    return;
  
  // We detect if the condition is performing a null-check on "za_state" rather than "sve_state".
  // Use ExprHasName to detect source text mentions.
  // If the condition references "za_state" but not "sve_state", then we suspect a mismatched check.
  if (ExprHasName(ConditionExpr, "za_state", C) && !ExprHasName(ConditionExpr, "sve_state", C)) {
    ProgramStateRef State = C.getState();
    const bool *Pending = State->get<AllocMap>(PendingSveKey);
    
    // If we had previously recorded a pending allocation of sve_state...
    if (Pending && *Pending) {
      // Report an issue: the allocation to sve_state is not being verified because the null-check
      // erroneously checks za_state.
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      
      auto report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Mismatched null-check: kzalloc allocation into sve_state is not verified (za_state is checked instead)", N);
      report->addRange(Condition->getSourceRange());
      C.emitReport(std::move(report));
      
      // Clear the flag by setting the pending allocation flag to false.
      State = State->set<AllocMap>(PendingSveKey, false);
      C.addTransition(State);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects mismatched null-check after kzalloc: allocation into sve_state is erroneously verified via za_state",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
