#include "clang/AST/Expr.h"
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

class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked Multiplication in Allocation")) { }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to detect multiplication operator in an expression.
  const BinaryOperator* findMultiplicationOperator(const Expr *E) const {
    if (!E)
      return nullptr;
    // Attempt to locate a BinaryOperator with '*' inside the children.
    if (const BinaryOperator *BO = findSpecificTypeInChildren<BinaryOperator>(E))
      if (BO->getOpcode() == BO_Mul)
        return BO;
    return nullptr;
  }
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Get the original call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use utility function to check for function name "kzalloc".
  if (!ExprHasName(OriginExpr, "kzalloc", C))
    return;
  
  // Ensure there is at least one argument.
  if (Call.getNumArgs() < 1)
    return;
  
  // Retrieve the first argument which is the allocation size.
  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;
  
  // Check if there is an unchecked multiplication in the allocation size.
  const BinaryOperator *MulExpr = findMultiplicationOperator(SizeArg->IgnoreImpCasts());
  if (!MulExpr)
    return;
  
  // If we found a multiplication operator, then warn the user.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Use PathSensitiveBugReport to report the bug with the appropriate API.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked multiplication detected in allocation; use kcalloc() to avoid integer overflow", 
      N);
  Report->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked multiplication in allocation size computation in kzalloc calls", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
