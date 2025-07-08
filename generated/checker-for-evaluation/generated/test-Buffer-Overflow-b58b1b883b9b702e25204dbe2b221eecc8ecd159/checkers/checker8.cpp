#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
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

// Add your includes here if needed

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states: Tracking whether a given iter->count has been checked.
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedCountMap, const MemRegion *, bool)

namespace {

/// Helper: Check if a MemberExpr refers to the "count" field.
/// This is used to determine if we are looking at iter->count.
bool isCountMember(const MemberExpr *ME) {
  if (!ME)
    return false;
  // Use the member name to check.
  return ME->getMemberNameInfo().getAsString() == "count";
}

/// The Checker class. It uses two callbacks:
/// 1. checkPreStmt for CompoundAssignOperators (e.g. "-=") on iter->count.
/// 2. checkBranchCondition for branch conditions that verify the safety of the subtraction.
class SAGenTestChecker 
  : public Checker< check::PreStmt<CompoundAssignOperator>,
                    check::BranchCondition >
{
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker() 
     : BT(new BugType(this, "Count Underflow Risk",
                        "Subtraction without safety check may underflow the count")) {}

   // Callback: Invoked before a statement is processed.
   void checkPreStmt(const CompoundAssignOperator *CA, CheckerContext &C) const;

   // Callback: Invoked when a branch condition is encountered.
   void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
   // Optional helper function to mark a given iter->count (memory region) as checked.
   ProgramStateRef markCountChecked(const MemRegion *MR, ProgramStateRef State) const {
     if (!MR)
       return State;
     MR = MR->getBaseRegion();
     return State->set<CheckedCountMap>(MR, true);
   }
};

void SAGenTestChecker::checkPreStmt(const CompoundAssignOperator *CA,
                                      CheckerContext &C) const {
  // We are only interested in subtraction assignments.
  if (CA->getOpcode() != BO_Sub)
    return;

  // Get the left-hand side of the assignment.
  const Expr *LHS = CA->getLHS()->IgnoreParenCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(LHS);
  if (!ME)
    return;

  // Check if the member being modified is "count".
  if (!isCountMember(ME))
    return;

  // Retrieve the memory region corresponding to iter->count.
  const MemRegion *MR = getMemRegionFromExpr(ME, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedCountMap>(MR);

  // If the region has not been marked as checked, then we report a bug.
  if (!(Checked && *Checked)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
                      *BT,
                      "Underflow risk: subtraction adjustment may exceed count",
                      N);
    Report->addRange(ME->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                              CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // We are interested in branch conditions that compare two values using '>='.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Condition)) {
    if (BO->getOpcode() == BO_GE) {
      // Attempt to find a MemberExpr within the condition that corresponds to "count".
      const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(BO);
      if (ME && isCountMember(ME)) {
        const MemRegion *MR = getMemRegionFromExpr(ME, C);
        if (MR) {
          MR = MR->getBaseRegion();
          // Mark the region as having been checked.
          State = State->set<CheckedCountMap>(MR, true);
          C.addTransition(State);
          return;
        }
      }
    }
  }
  // For conditions that are not handled, just propagate the current state.
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential underflow in iov_iter count subtraction without a proper check", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
