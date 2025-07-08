#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is needed for this checker.

namespace {

/// This checker detects a subtraction from iter->count that might underflow
/// because the computed shorten value is not properly guarded.
/// It inspects compound assignments (of '-=') on "iter->count" whose right-hand side
/// is computed as "iov_iter_count(iter) - round_up(...)" and then checks that a guard
/// condition ("if (shorten >= iter->count)") is present in the control-flow.
///
/// The checker uses checkPreStmt on BinaryOperator nodes.
class SAGenTestChecker
    : public Checker< check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this,
         "Underflow risk",
         "Subtraction from iter->count without proper bound check")) {}

  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;

private:
  /// Helper to decide if the BinaryOperator represents the target subtraction.
  bool isTargetSubtraction(const BinaryOperator *B, CheckerContext &C) const;

  /// Helper to determine whether a guarding if-statement exists.
  bool hasGuardingIf(const BinaryOperator *B, CheckerContext &C) const;

  /// Report a bug.
  void reportBug(const BinaryOperator *B, CheckerContext &C) const;
};

bool SAGenTestChecker::isTargetSubtraction(const BinaryOperator *B,
                                             CheckerContext &C) const {
  // We are interested in '-=' operators.
  if (B->getOpcode() != BO_SubAssign)
    return false;

  // Check if the left-hand side (LHS) text contains "iter->count".
  const Expr *LHS = B->getLHS()->IgnoreParenImpCasts();
  if (!LHS)
    return false;
  if (!ExprHasName(LHS, "iter->count", C))
    return false;

  // Optionally, you can check if the right-hand side (RHS) contains part of the target computation.
  // For example, check if it mentions "iov_iter_count".
  const Expr *RHS = B->getRHS()->IgnoreParenImpCasts();
  if (!RHS)
    return false;
  if (!ExprHasName(RHS, "iov_iter_count", C))
    return false;

  // We assume this pattern is unique enough.
  return true;
}

bool SAGenTestChecker::hasGuardingIf(const BinaryOperator *B,
                                       CheckerContext &C) const {
  // Search upward in the AST for an if-statement.
  const IfStmt *IfParent = findSpecificTypeInParents<IfStmt>(B, C);
  if (!IfParent)
    return false;

  // Check the condition of the if statement.
  const Expr *Cond = IfParent->getCond();
  if (!Cond)
    return false;

  // We want to see if the condition involves comparing "shorten" and "iter->count".
  // Use ExprHasName utility on the condition to see if both identifiers are present.
  bool HasShorten = ExprHasName(Cond, "shorten", C);
  bool HasCount   = ExprHasName(Cond, "iter->count", C);

  // We are only interested in guard conditions that explicitly mention both.
  return (HasShorten && HasCount);
}

void SAGenTestChecker::reportBug(const BinaryOperator *B,
                                   CheckerContext &C) const {
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Underflow risk: subtraction from iter->count without proper bound check", N);
    Report->addRange(B->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *B,
                                      CheckerContext &C) const {
  // Only proceed if we match the subtraction pattern.
  if (!isTargetSubtraction(B, C))
    return;

  // If a guard exists, then no bug.
  if (hasGuardingIf(B, C))
    return;

  // Otherwise, report the bug.
  reportBug(B, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects subtraction from iter->count without ensuring the shorten value is less than count",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
