#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Mixed-type Multiplication", "Integer Overflow")) {}

  // Callback: Check every multiplication operation.
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  // Only consider multiplication expression.
  if (BO->getOpcode() != BO_Mul)
    return;

  // Retrieve left-hand side and right-hand side operands.
  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType LHSTy = LHS->getType();
  QualType RHSTy = RHS->getType();

  // Only proceed if both operands are of an integer type.
  if (!LHSTy->isIntegerType() || !RHSTy->isIntegerType())
    return;

  // Get the canonical types for effective comparison.
  QualType CanLHS = LHSTy.getCanonicalType();
  QualType CanRHS = RHSTy.getCanonicalType();

  // If the two types are identical, then there is no mixing.
  if (CanLHS == CanRHS)
    return;

  // Optionally, further check if the types have different sizes.
  // If both types have the same size (in bits), the risk might be lower.
  if (C.getASTContext().getTypeSize(CanLHS) == C.getASTContext().getTypeSize(CanRHS))
    return;

  // A multiplication with operands of different integer types (with distinct sizes)
  // may lead to unintentional integer overflow.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Multiplication of mixed integer types may lead to unintentional integer overflow",
      N);
  report->addRange(BO->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects multiplication of mixed integer types that may cause integer overflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
