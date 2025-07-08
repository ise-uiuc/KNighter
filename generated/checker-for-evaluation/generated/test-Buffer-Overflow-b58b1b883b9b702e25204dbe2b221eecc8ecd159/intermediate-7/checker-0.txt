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
#include "clang/Basic/OperatorKinds.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unsigned underflow risk in iter->count subtraction")) {}

  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;

private:
  void reportUnderflow(const BinaryOperator *B, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const BinaryOperator *B, CheckerContext &C) const {
  // Only target '-=' operators.
  if (B->getOpcode() != BO_SubAssign)
    return;

  const Expr *LHS = B->getLHS();
  if (!LHS)
    return;

  // Check if the LHS expression appears to be "iter->count"
  if (!ExprHasName(LHS, "iter->count", C))
    return;

  const Expr *RHS = B->getRHS();
  if (!RHS)
    return;

  llvm::APSInt LHSVal, RHSVal;
  bool canEvalLHS = EvaluateExprToInt(LHSVal, LHS, C);
  bool canEvalRHS = EvaluateExprToInt(RHSVal, RHS, C);

  // If both operands can be evaluated to constants,
  // then check if subtracting RHS from LHS could underflow.
  if (canEvalLHS && canEvalRHS) {
    if (RHSVal >= LHSVal)
      reportUnderflow(B, C);
  }
  // Otherwise, conservatively do not report to avoid false positives.
}

void SAGenTestChecker::reportUnderflow(const BinaryOperator *B, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Underflow risk: subtraction may underflow iter->count", N);
  Report->addRange(B->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unsigned underflow risk on iter->count subtraction due to oversized shorten value", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
