```cpp
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
#include "clang/AST/Expr.h"  // Added for Expr and CastExpr

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker detects left-shift operations computed on lower-width (e.g., 32-bit)
// integers which should have been upcast to 64-bit before applying the shift. The lack
// of an explicit cast to a wider type can lead to an integer overflow.
class SAGenTestChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Integer overflow due to missing upcast", "Integer Overflow")) {}

  // This callback examines every BinaryOperator statement.
  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;

private:
  // Helper function that checks whether an expression (or any of its children or parents)
  // is explicitly cast to a 64-bit (or wider) integer type.
  bool hasUpcastTo64(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::hasUpcastTo64(const Expr *E, CheckerContext &C) const {
  // Remove any implicit casts for our check.
  E = E->IgnoreImplicit();

  // First, if E itself is a cast expression, check its cast type.
  if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    QualType castTy = CE->getType();
    if (castTy->isIntegerType() && C.getASTContext().getTypeSize(castTy) >= 64)
      return true;
  }

  // Next, check if any child of E is an explicit cast to a 64-bit type
  if (const CastExpr *childCast = findSpecificTypeInChildren<CastExpr>(E)) {
    QualType castTy = childCast->getType();
    if (castTy->isIntegerType() && C.getASTContext().getTypeSize(castTy) >= 64)
      return true;
  }

  // Finally, check if any parent of E is an explicit cast to a 64-bit type.
  if (const CastExpr *parentCast = findSpecificTypeInParents<CastExpr>(E, C)) {
    QualType castTy = parentCast->getType();
    if (castTy->isIntegerType() && C.getASTContext().getTypeSize(castTy) >= 64)
      return true;
  }

  return false;
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *B, CheckerContext &C) const {
  // Only process left-shift (<<) operations.
  if (B->getOpcode() != BO_Shl)
    return;

  const Expr *LHS = B->getLHS();
  if (!LHS)
    return;

  // We are interested only in integer left-hand operands.
  QualType lhsType = LHS->getType();
  if (!lhsType->isIntegerType())
    return;

  // If the LHS type already has a bit-width of 64 or more, it is safe.
  unsigned lhsWidth = C.getASTContext().getTypeSize(lhsType);
  if (lhsWidth >= 64)
    return;

  // Check whether an explicit cast to a 64-bit type exists on the left-hand side.
  if (!hasUpcastTo64(LHS, C)) {
    // No safe cast was found: report a potential bug.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
         *BT,
         "Potential integer overflow: upcast to 64-bit missing before left-shift", N);
    report->addRange(B->getSourceRange());
    C.emitReport(std::move(report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects left-shift operations on 32-bit integers that risk overflow due to missing upcast to 64-bit", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
```