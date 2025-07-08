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
#include "clang/Lex/Lexer.h"  // For getting source text

using namespace clang;
using namespace ento;
using namespace taint;

// Customize Program State Map to record whether a max_entries value is safe.
// The boolean flag is true if the value has been pre-checked against the safe threshold.
REGISTER_MAP_WITH_PROGRAMSTATE(SafeMaxEntriesMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked rounding up", "Integer Overflow")) {}

  // Callback for branch conditions.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  // Callback for function calls.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper to report an error for unchecked roundup_pow_of_two usage.
  void reportUncheckedRoundup(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const;
};

//////////////////////////////////////////////////////////////////////////
// checkBranchCondition
//////////////////////////////////////////////////////////////////////////
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // We want to detect if the branch condition involves checking max_entries against a safe threshold.
  // Use the utility function ExprHasName to check if the condition text contains "max_entries"
  // and "1UL << 31". This indicates a safe-guard is in place.
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  
  // Check if the condition source text has the substrings "max_entries" and "1UL << 31".
  if (ExprHasName(CondE, "max_entries", C) && 
      ExprHasName(CondE, "1UL << 31", C)) {
    // Try to locate the DeclRefExpr for "max_entries" in the condition.
    const DeclRefExpr *MaxEntriesDRE = findSpecificTypeInChildren<DeclRefExpr>(Condition);
    if (MaxEntriesDRE) {
      // Ensure that the DeclRefExpr name is exactly "max_entries".
      if (MaxEntriesDRE->getDecl()->getNameAsString() == "max_entries") {
        const MemRegion *MR = getMemRegionFromExpr(MaxEntriesDRE, C);
        if (MR) {
          MR = MR->getBaseRegion();
          // Mark the associated region as safe in our program state.
          State = State->set<SafeMaxEntriesMap>(MR, true);
          C.addTransition(State);
          return;
        }
      }
    }
  }
  C.addTransition(State);
}

//////////////////////////////////////////////////////////////////////////
// checkPreCall
//////////////////////////////////////////////////////////////////////////
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Use the utility function ExprHasName to check that the call's origin expression
  // corresponds to the function 'roundup_pow_of_two'
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "roundup_pow_of_two", C))
    return;

  // Retrieve the call expression.
  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE)
    return;
  
  // Ensure there is at least one argument.
  if (CE->getNumArgs() < 1)
    return;
  
  // Get the argument expression for roundup_pow_of_two.
  const Expr *ArgExpr = CE->getArg(0);
  if (!ArgExpr)
    return;

  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  // Check if this max_entries value has been safely checked.
  const bool *IsSafe = State->get<SafeMaxEntriesMap>(MR);
  if (!IsSafe || (*IsSafe == false)) {
    // Not safe--report error.
    reportUncheckedRoundup(Call, C, MR);
  }
  C.addTransition(State);
}

//////////////////////////////////////////////////////////////////////////
// reportUncheckedRoundup: Report bug if unchecked rounding is used.
//////////////////////////////////////////////////////////////////////////
void SAGenTestChecker::reportUncheckedRoundup(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked use of roundup_pow_of_two: max_entries value not validated against safe threshold", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked use of roundup_pow_of_two that may overflow on 32-bit arches", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
