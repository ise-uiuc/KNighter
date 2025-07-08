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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Type.h"
#include "clang/Basic/OperatorKinds.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Our checker only needs to implement checkPreCall.
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Integer Overflow in kzalloc Multiplication")) {}

  // Callback: checkPreCall is invoked before every function call.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper: Returns true if the given expression is a sizeof expression.
  bool isSizeOfExpr(const Expr *E) const {
    if (!E)
      return false;
    // Remove any parens or casts.
    E = E->IgnoreParenCasts();
    return isa<UnaryExprOrTypeTraitExpr>(E);
  }
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin (concrete) call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use the utility function ExprHasName to ensure the call is to "kzalloc".
  if (!ExprHasName(OriginExpr, "kzalloc", C))
    return;

  // kzalloc is typically called with at least one argument: the allocation size.
  if (Call.getNumArgs() < 1)
    return;
  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;
  SizeArg = SizeArg->IgnoreParenCasts();

  // Look downward in the AST of SizeArg for a binary multiplication operation.
  const BinaryOperator *MulExpr = findSpecificTypeInChildren<BinaryOperator>(SizeArg);
  if (!MulExpr)
    return; // Pattern not found: no multiplication expression in the size argument.

  // Check if the binary operator is a multiplication.
  if (MulExpr->getOpcode() != BO_Mul)
    return;

  // Check the operands of the multiplication to see if one is a sizeof expression.
  const Expr *LHS = MulExpr->getLHS()->IgnoreParenCasts();
  const Expr *RHS = MulExpr->getRHS()->IgnoreParenCasts();
  if (!isSizeOfExpr(LHS) && !isSizeOfExpr(RHS))
    return;

  // We have detected a multiplication inside kzalloc's allocation argument
  // that involves a sizeof expression. This is a potential integer overflow risk.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential integer overflow in multiplication argument of kzalloc; consider using kcalloc for overflow safety",
      N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential integer overflow when kzalloc multiplies allocation parameters; use kcalloc instead",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
