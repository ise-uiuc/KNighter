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
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker intercepts assignments and looks for a case where a 32-bit
// multiplication is performed and then assigned to a 64-bit variable.
class SAGenTestChecker : public Checker< check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Integer overflow", "Integer Overflow")) {}

  // Callback invoked when a value is bound to a memory location.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper used to report a bug.
  void reportBug(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Attempt to find a BinaryOperator in the statement.
  const BinaryOperator *AssignOp = dyn_cast_or_null<BinaryOperator>(S);
  if (!AssignOp)
    // Try to locate a BinaryOperator in the children if S is not directly one.
    AssignOp = findSpecificTypeInChildren<BinaryOperator>(S);
  if (!AssignOp)
    return;

  // Check that the operator is an assignment.
  if (AssignOp->getOpcode() != BO_Assign)
    return;

  // Retrieve the left-hand side. We need its type.
  const Expr *LHS = AssignOp->getLHS();
  if (!LHS)
    return;
  QualType LHSType = LHS->getType();
  ASTContext &Ctx = C.getASTContext();

  // Check that the left-hand side is an integer type and has a width of 64 bits.
  if (!LHSType->isIntegerType())
    return;
  if (Ctx.getTypeSize(LHSType) != 64)
    return;

  // Process the right-hand side of the assignment.
  const Expr *RHS = AssignOp->getRHS();
  if (!RHS)
    return;
  
  // Remove any implicit casts and parens.
  const Expr *CoreRHS = RHS->IgnoreParenCasts();

  // Look for a multiplication operator in the RHS.
  const BinaryOperator *MulOp = nullptr;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CoreRHS)) {
    if (BO->getOpcode() == BO_Mul)
      MulOp = BO;
  }
  if (!MulOp)
    // Try to find a multiplication operator in the subtree.
    MulOp = findSpecificTypeInChildren<BinaryOperator>(CoreRHS);
  if (!MulOp || MulOp->getOpcode() != BO_Mul)
    return;

  // Check that both operands of the multiplication are present.
  const Expr *MulLHS = MulOp->getLHS();
  const Expr *MulRHS = MulOp->getRHS();
  if (!MulLHS || !MulRHS)
    return;

  // Verify that both operands are integer types.
  QualType MulLHSType = MulLHS->getType();
  QualType MulRHSType = MulRHS->getType();
  if (!MulLHSType->isIntegerType() || !MulRHSType->isIntegerType())
    return;

  // Check that both operands are 32-bit integers.
  if (Ctx.getTypeSize(MulLHSType) != 32 || Ctx.getTypeSize(MulRHSType) != 32)
    return;

  // Also check the multiplication operation's result type is 32-bit.
  QualType MulResultType = MulOp->getType();
  if (!MulResultType->isIntegerType())
    return;
  if (Ctx.getTypeSize(MulResultType) != 32)
    return;

  // The pattern is detected: a multiplication of two 32-bit integers (performed in 32-bit)
  // is being assigned to a 64-bit variable without an intermediate cast.
  reportBug(S, C);
}

void SAGenTestChecker::reportBug(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential integer overflow: 32-bit multiplication used for 64-bit assignment", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects 32-bit multiplications assigned to 64-bit variables without casting", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
