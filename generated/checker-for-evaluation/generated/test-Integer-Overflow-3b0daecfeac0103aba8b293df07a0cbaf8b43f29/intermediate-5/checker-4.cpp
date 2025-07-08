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
#include "clang/StaticAnalyzer/Core/PathDiagnosticLocation.h" // Fixed header inclusion

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Multiplication in allocation can overflow")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to determine if an expression contains a multiplication
  // operation with a sizeof operator as one of its subexpressions.
  bool containsSizeofMultiplication(const Expr *E) const {
    if (!E)
      return false;
    
    // Search for a BinaryOperator in the AST children.
    const BinaryOperator *BinOp = findSpecificTypeInChildren<BinaryOperator>(E);
    if (!BinOp)
      return false;
    
    // Check if the binary operator is multiplication.
    if (BinOp->getOpcode() != BO_Mul)
      return false;

    // Check if either operand involves a sizeof operator.
    const Expr *LHS = BinOp->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BinOp->getRHS()->IgnoreParenCasts();
    if (isa<UnaryExprOrTypeTraitExpr>(LHS) || isa<UnaryExprOrTypeTraitExpr>(RHS))
      return true;
    
    return false;
  }
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the call's origin expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check that this call is to a function named "kzalloc"
  // Using the utility function for name checking.
  if (!ExprHasName(OriginExpr, "kzalloc", C))
    return;
  
  // Ensure there is at least one argument.
  if (Call.getNumArgs() < 1)
    return;

  // Retrieve the allocation size argument.
  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;

  // If the size argument contains a multiplication with a sizeof, then report.
  if (containsSizeofMultiplication(SizeArg)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(SizeArg,
      C.getSourceManager(), C.getLocationContext());

    auto Report = std::make_unique<BasicBugReport>(*BT,
         "Multiplication in allocation can overflow", Loc);
    Report->addRange(SizeArg->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects multiplication expressions in allocation calls that can overflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
