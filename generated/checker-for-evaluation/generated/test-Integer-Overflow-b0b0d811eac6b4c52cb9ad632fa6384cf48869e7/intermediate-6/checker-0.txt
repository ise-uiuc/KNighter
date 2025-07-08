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

namespace {

// This checker detects mixed-type multiplication that may lead to integer overflow.
class SAGenTestChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Mixed-type multiplication", "Arithmetic Issues")) {}

  // Callback for visiting BinaryOperator statements.
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

private:
  // Helper function to report a bug.
  void reportMixedTypeMultiplication(const BinaryOperator *BO, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  // Only process multiplication operators.
  if (BO->getOpcode() != BO_Mul)
    return;

  // Retrieve the left-hand side and right-hand side expressions.
  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType LHSType = LHS->getType();
  QualType RHSType = RHS->getType();

  // Proceed only if both operands are of integer type.
  if (!LHSType->isIntegerType() || !RHSType->isIntegerType())
    return;

  // Compare the canonical (unqualified) types.
  if (LHSType.getCanonicalType() != RHSType.getCanonicalType()) {
    // Optionally: check if this multiplication is part of an assignment
    // by going upward in the AST. We can use the utility function if desired:
    // const BinaryOperator *ParentOp = findSpecificTypeInParents<BinaryOperator>(BO, C);
    // For now, we simply report all mixed-type multiplications.

    reportMixedTypeMultiplication(BO, C);
  }
}

void SAGenTestChecker::reportMixedTypeMultiplication(const BinaryOperator *BO, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create a short, clear bug report.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Mixed-type multiplication may lead to integer overflow", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects mixed-type multiplication between different integer types that may cause overflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
