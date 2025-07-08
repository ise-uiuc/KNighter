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
#include "clang/AST/Expr.h"  // For BinaryOperator

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker detects potential integer overflows in allocation size computation
// when using kzalloc() by checking if a multiplication expression is used to compute
// the allocation size. The recommended fix is to use kcalloc() instead.
class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Allocation", "Security")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportBug(const CallEvent &Call, CheckerContext &C, const Expr *ProblemExpr) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Potential integer overflow in allocation; use kcalloc instead", N);
    report->addRange(ProblemExpr->getSourceRange());
    C.emitReport(std::move(report));
  }
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression of the call.
  const Expr *OriginE = Call.getOriginExpr();
  if (!OriginE)
    return;
  
  // Use the utility function ExprHasName to check if the call is to "kzalloc".
  if (!ExprHasName(OriginE, "kzalloc", C))
    return;
  
  // Expect kzalloc to be called with at least one argument.
  if (Call.getNumArgs() < 1)
    return;

  // Retrieve the allocation size argument.
  const Expr *AllocSizeExpr = Call.getArgExpr(0);
  if (!AllocSizeExpr)
    return;
  
  // Perform a downward AST traversal on the allocation size expression to search for a BinaryOperator.
  const BinaryOperator *BO = findSpecificTypeInChildren<BinaryOperator>(AllocSizeExpr);
  if (!BO)
    return;
  
  // If the BinaryOperator is a multiplication, it indicates that the allocation size
  // is computed by multiplying two values, which can lead to an integer overflow.
  if (BO->getOpcode() != BO_Mul)
    return;
  
  // Report the potential vulnerability.
  reportBug(Call, C, AllocSizeExpr);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential integer overflow when computing allocation size with kzalloc; use kcalloc instead",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
