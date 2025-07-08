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

// Additional includes required for AST node manipulation.
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ExprCXX.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker< check::PostCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Integer overflow risk",
    "kzalloc multiplication overflow")) {}

  // Callback function: Post-call for function calls.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // (No additional self-defined functions are required for this checker.)
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the utility function ExprHasName to confirm that the call is to "kzalloc".
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "kzalloc", C))
    return;
  
  // Ensure there is at least one argument for kzalloc.
  if (Call.getNumArgs() < 1)
    return;

  // Retrieve the size argument (the first argument).
  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;

  // Look downward in the AST of the size argument for a multiplication operator.
  // Using the provided utility function findSpecificTypeInChildren.
  const BinaryOperator *MulOp = findSpecificTypeInChildren<BinaryOperator>(SizeArg);
  if (!MulOp)
    return;

  // Check if the identified BinaryOperator is a multiplication.
  if (MulOp->getOpcode() != BO_Mul)
    return;

  // At this point we have identified a multiplication in the size argument to kzalloc,
  // which could overflow. Hence, we report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Integer overflow risk: Multiplication in kzalloc size argument; consider using kcalloc to avoid overflow", N);
  Report->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential integer overflow when kzalloc uses multiplication to compute size", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
