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

// Additional includes needed for AST inspection.
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Checker that inspects calls to copy_from_user() for manual multiplication.
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Manual buffer size computation", "Kernel Security")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper: Check if the given expression contains a binary multiplication
  // with an embedded sizeof operator.
  bool containsManualMultiplication(const Expr *E) const {
    if (!E)
      return false;

    // Look for a multiplication binary operator in the children of the expression.
    const BinaryOperator *BO = findSpecificTypeInChildren<BinaryOperator>(E);
    if (!BO)
      return false;

    // We are interested only in multiplication (*) operations.
    if (BO->getOpcode() != BO_Mul)
      return false;

    // Using utility helper to search for a UnaryExprOrTypeTraitExpr expression.
    const UnaryExprOrTypeTraitExpr *UET = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(BO);
    if (!UET)
      return false;

    // Confirm that the trait is sizeof.
    if (UET->getKind() != UETT_SizeOf)
      return false;

    return true;
  }
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression to inspect the source code text.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use the utility function to check if the call's source text contains "copy_from_user".
  // This helps ensure we are only analyzing the proper call.
  if (!ExprHasName(OriginExpr, "copy_from_user", C))
    return;

  // Ensure the call has at least three arguments.
  if (Call.getNumArgs() < 3)
    return;
  
  // Retrieve the third argument (index 2) which represents the buffer size.
  const Expr *SizeArg = Call.getArgExpr(2);
  if (!SizeArg)
    return;

  // If array_size() helper is already used, then there is no issue.
  if (ExprHasName(SizeArg, "array_size", C))
    return;

  // Check if the third argument is computed via multiplication containing a sizeof operator.
  if (containsManualMultiplication(SizeArg)) {
    // Generate a non-fatal error node.
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Possible integer overflow in manual buffer size computation; consider using array_size()", N);
      Report->addRange(SizeArg->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects manual multiplication for buffer size computation without overflow check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
