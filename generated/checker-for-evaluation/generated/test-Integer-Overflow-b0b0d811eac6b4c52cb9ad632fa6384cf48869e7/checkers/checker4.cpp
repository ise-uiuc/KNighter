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

// Add your includes here
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No additional program state is required for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Multiplication Type Mismatch",
                     "Potential integer overflow due to implicit type conversion")) {}

  void checkPreStmt(const BinaryOperator *BOP, CheckerContext &C) const;

private:
  // Helper function to decide if the multiplication expression has mismatched operand types.
  bool hasMismatchedTypes(const Expr *LHS, const Expr *RHS, ASTContext &Ctx) const {
    // Retrieve the canonical types for both operands.
    QualType LHSType = LHS->getType().getCanonicalType();
    QualType RHSType = RHS->getType().getCanonicalType();
    
    // If the types are identical, no mismatch.
    if (LHSType == RHSType)
      return false;
      
    // For our bug pattern, we only need to flag the case if one (or both)
    // operand types are different, and at least one of them is known to be of interest.
    // In our example, we are particularly interested in cases where one of the types
    // is "dma_addr_t".  However, to be general, we flag any multiplication between 
    // different types.
    return true;
  }
};

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BOP,
                                      CheckerContext &C) const {
  // Only interested in multiplication operations.
  if (BOP->getOpcode() != BO_Mul)
    return;
    
  const Expr *LHS = BOP->getLHS();
  const Expr *RHS = BOP->getRHS();
  if (!LHS || !RHS)
    return;
    
  ASTContext &Ctx = C.getASTContext();
  if (!hasMismatchedTypes(LHS, RHS, Ctx))
    return;

  // Generate an error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  // Create a bug report with a short clear message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Multiplication between variables of different types may overflow", N);
  Report->addRange(BOP->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects multiplication expressions between variables of different types which can cause unintended integer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
