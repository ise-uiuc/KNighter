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
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to record valid allocations 
// from kzalloc assigned to the expected pointer ("sve_state").
REGISTER_MAP_WITH_PROGRAMSTATE(AllocationMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "NULL check on wrong pointer", "Memory Allocation")) {}

  // Callback invoked when a value gets bound to a memory region.
  // We use this to detect member assignments to dst->thread.sve_state.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

  // Callback invoked in branch conditions (e.g., in if-statements).
  // We use this to detect when the code erroneously performs a NULL check on za_state.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportWrongNullCheck(const Stmt *Condition, CheckerContext &C) const;
};

//
// Implementation of checkBind:
// We look for a binding into a MemberExpr whose field name is "sve_state"
// and whose right-hand side is a call to kzalloc().
// If found, we record the allocation in our AllocationMap using the base region.
//
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Look downward in S for a MemberExpr.
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(S);
  if (!ME)
    return;

  // Check if this binding is for the field "sve_state".
  IdentifierInfo *FieldId = ME->getMemberDecl()->getIdentifier();
  if (!FieldId || FieldId->getName() != "sve_state")
    return;

  // Now, look for a CallExpr in the children, which should be the rhs of the assignment.
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE)
    return;
  
  // Use the utility function to confirm that the call is to kzalloc.
  if (!ExprHasName(CE, "kzalloc", C))
    return;

  // Retrieve the memory region for the left-hand side.
  const MemRegion *LHSRegion = Loc.getAsRegion();
  if (!LHSRegion)
    return;
  const MemRegion *BaseReg = LHSRegion->getBaseRegion();
  if (!BaseReg)
    return;

  // Mark this base region in AllocationMap as having a valid allocation.
  ProgramStateRef State = C.getState();
  State = State->set<AllocationMap>(BaseReg, true);
  C.addTransition(State);
}

//
// Implementation of checkBranchCondition:
// We intercept if-conditions and check if the condition is performing a NULL check
// on "za_state" (using its textual representation).
// If so, we then verify if a valid allocation was previously recorded for "sve_state"
// (by checking the AllocationMap on an appropriate region).
// If the allocation exists, then the null check is done on the wrong pointer.
//
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;
    
  // Use the utility function to check if the condition’s source text contains "za_state".
  if (!ExprHasName(cast<Expr>(Condition), "za_state", C))
    return;
  
  // Try to locate the MemberExpr corresponding to the NULL check.
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Condition);
  if (!ME)
    return;
  
  IdentifierInfo *FieldId = ME->getMemberDecl()->getIdentifier();
  if (!FieldId || FieldId->getName() != "za_state")
    return;
  
  // Retrieve the memory region for the member expression.
  const MemRegion *R = getMemRegionFromExpr(ME, C);
  if (!R)
    return;
  const MemRegion *BaseReg = R->getBaseRegion();
  if (!BaseReg)
    return;
  
  // Check in AllocationMap if a valid kzalloc allocation was recorded on the "sve_state" member.
  ProgramStateRef State = C.getState();
  const bool *Allocated = State->get<AllocationMap>(BaseReg);
  
  // If there is a corresponding allocation (i.e. true), then the NULL check is on "za_state" even though
  // the allocation was made to "sve_state". Report the bug.
  if (Allocated && *Allocated) {
    reportWrongNullCheck(Condition, C);
  }
}

//
// Helper function to report the wrong NULL check bug.
// Emits a non-fatal error node with a short, clear message.
//
void SAGenTestChecker::reportWrongNullCheck(const Stmt *Condition, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "NULL check on wrong pointer: allocated memory is bound to 'sve_state' but NULL check is on 'za_state'",
      N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects incorrect NULL check on a wrong pointer variable after kzalloc", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
