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
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to record allocation for a specific field.
// Key: The base MemRegion for the containing object (e.g. dst->thread).
// Value: The field name that was allocated (e.g. "sve_state").
REGISTER_MAP_WITH_PROGRAMSTATE(AllocMap, const MemRegion*, llvm::StringRef)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL check on wrong pointer",
                       "Memory error")) {}

  // Callback: called after a function call's evaluation.
  // We intercept kzalloc calls to record an allocation if it is used to set "sve_state".
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: called when evaluating branch conditions (e.g., inside an if-statement).
  // Detect if a NULL check is performed on a field "za_state" when an allocation on "sve_state" has been recorded.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper: Report a bug at the given node with a short message.
  void reportWrongNullCheck(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Intercept calls to kzalloc only.
  // Instead of using a non-existent getCalleeNameAsExpr, we use getCalleeName().
  if (Call.getCalleeName() != "kzalloc")
    return;

  // We expect this kzalloc call to be part of an assignment.
  // Traverse upward in the AST to try to find a MemberExpr.
  const MemberExpr *ME = findSpecificTypeInParents<MemberExpr>(OriginExpr, C);
  if (!ME)
    return;

  // Check if the field being assigned is "sve_state".
  if (!ExprHasName(ME, "sve_state", C))
    return;

  // Obtain the base of the MemberExpr that represents the parent object.
  const Expr *BaseExpr = ME->getBase();
  if (!BaseExpr)
    return;

  // Get the MemRegion for the base object without stripping implicit casts.
  const MemRegion *ParentRegion = getMemRegionFromExpr(BaseExpr, C);
  if (!ParentRegion)
    return;
  ParentRegion = ParentRegion->getBaseRegion();
  if (!ParentRegion)
    return;

  // Record in the AllocMap that this base object had an allocation on "sve_state".
  State = State->set<AllocMap>(ParentRegion, "sve_state");
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition)
    return;

  // We handle conditions that involve a NULL check.
  // For simplicity, we focus on the unary operator '!' checking a member expression.
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  // Remove any parentheses or casts.
  CondExpr = CondExpr->IgnoreParenCasts();

  // Check if this is a unary NOT operation.
  if (const auto *UO = dyn_cast<UnaryOperator>(CondExpr)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubExpr = UO->getSubExpr()->IgnoreParenCasts();
      // Check if the subexpression is a MemberExpr.
      if (const MemberExpr *ME = dyn_cast<MemberExpr>(SubExpr)) {
        // We are looking for a check on "za_state" which is suspicious.
        if (ExprHasName(ME, "za_state", C)) {
          // Get the base object of the member expression.
          const Expr *BaseExpr = ME->getBase();
          if (!BaseExpr)
            return;
          const MemRegion *ParentRegion = getMemRegionFromExpr(BaseExpr, C);
          if (!ParentRegion)
            return;
          ParentRegion = ParentRegion->getBaseRegion();
          if (!ParentRegion)
            return;

          // Now check our AllocMap: if the parent object has a recorded allocation on "sve_state",
          // then a bug is present because the code is checking the wrong pointer.
          const llvm::StringRef *RecordedField = State->get<AllocMap>(ParentRegion);
          if (RecordedField && *RecordedField == "sve_state") {
            // Report the bug.
            reportWrongNullCheck(Condition, C);
          }
        }
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportWrongNullCheck(const Stmt *S, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create a bug report with a brief message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "NULL check on wrong pointer: expected check on sve_state", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects incorrect NULL pointer check after kzalloc (checks za_state instead of sve_state)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
