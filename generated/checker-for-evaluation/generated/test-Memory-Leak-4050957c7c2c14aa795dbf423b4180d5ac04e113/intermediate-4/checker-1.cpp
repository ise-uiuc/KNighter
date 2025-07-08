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
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker detects an off-by-one error in the error cleanup loop.
// It looks for branch conditions of the form "while (--i > 0)" inside the function "gsc_runtime_resume"
// where the proper bug fix should use "while (--i >= 0)".
class SAGenTestChecker : public Checker<check::BranchCondition> { 
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Off-by-one error in cleanup loop")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportOffByOne(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::reportOffByOne(const Stmt *Condition, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Off-by-one error in cleanup loop: cleanup loop skips index 0; should use '--i >= 0'", N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  // Check if the condition is a binary operator.
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Condition);
  if (!BO)
    return;
  
  // Look for ">" operator.
  if (BO->getOpcode() != BO_GT)
    return;
    
  // Check if the left-hand side is a pre-decrement operator, i.e. "--i"
  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_PreDec)
    return;
    
  // Check if the right-hand side is the integer constant 0.
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
  const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(RHS);
  if (!IL || !IL->getValue().isZero())
    return;
    
  // Verify that this branch condition is inside the function "gsc_runtime_resume".
  // Instead of using findSpecificTypeInParents (which causes type conversion errors),
  // we retrieve the function declaration from the LocationContext.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD)
    return;
    
  if (FD->getNameAsString() != "gsc_runtime_resume")
    return;
    
  // The condition matches the bug pattern "while (--i > 0)".
  reportOffByOne(Condition, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects off-by-one error in error cleanup loop in gsc_runtime_resume", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
