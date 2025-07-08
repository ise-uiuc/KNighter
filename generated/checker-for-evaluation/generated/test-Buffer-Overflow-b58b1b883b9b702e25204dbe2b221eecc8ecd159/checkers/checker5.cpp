#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
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

namespace {

/// SAGenTestChecker - This checker detects when subtraction is performed on the
/// "iter->count" field with "shorten" without a preceding check that ensures
/// that 'shorten' is less than iter->count, to prevent unsigned underflow.
class SAGenTestChecker 
  : public Checker< check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked Subtraction", 
                           "Subtraction without proper underflow-check")) {}

  void checkPreStmt(const BinaryOperator *BOp, CheckerContext &C) const;

private:
  /// reportUnderflow - Emits a bug report if the subtraction operation is not
  /// guarded by an appropriate check.
  void reportUnderflow(const BinaryOperator *BOp, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BOp, CheckerContext &C) const {
  // We are only interested in subtraction-assignment "-=" operators.
  if (BOp->getOpcode() != BO_SubAssign)
    return;
  
  // Check if the left-hand side text contains "iter->count".
  const Expr *LHS = BOp->getLHS();
  const Expr *RHS = BOp->getRHS();
  if (!LHS || !RHS)
    return;
  
  // Use utility function ExprHasName to check the source text.
  if (!ExprHasName(LHS, "iter->count", C))
    return;
  if (!ExprHasName(RHS, "shorten", C))
    return;

  // Look upward in the AST to detect an enclosing if-statement that
  // includes a check with "shorten >= iter->count".
  const IfStmt *IfR = findSpecificTypeInParents<IfStmt>(BOp, C);
  if (IfR) {
    const Expr *Cond = IfR->getCond();
    if (Cond && ExprHasName(Cond, "shorten >=", C) && ExprHasName(Cond, "iter->count", C)) {
      // A check is present; do not report a bug.
      return;
    }
  }
  
  // No appropriate check was found, report potential underflow.
  reportUnderflow(BOp, C);
}

void SAGenTestChecker::reportUnderflow(const BinaryOperator *BOp, CheckerContext &C) const {
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Underflow risk: unchecked subtraction may cause iter->count to underflow",
        N);
    Report->addRange(BOp->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects subtraction of 'shorten' from 'iter->count' without checking for underflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
