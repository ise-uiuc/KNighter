```cpp
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// The checker only needs to hook the PreStmt callback for BinaryOperator.
class SAGenTestChecker : public Checker< check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Potential 32-bit left shift without 64-bit upcasting")) {}

  void checkPreStmt(const BinaryOperator *BOp, CheckerContext &C) const;

private:
  // Helper function that uses downward AST traversal to look for a CastExpr that upcasts
  // an integer expression to a 64-bit type.
  bool isProperlyCastTo64(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::isProperlyCastTo64(const Expr *E, CheckerContext &C) const {
  // Look for any cast expression in the subtree of E.
  const CastExpr *CE = findSpecificTypeInChildren<CastExpr>(E);
  if (!CE)
    // Also check if E itself is a CastExpr.
    if (const CastExpr *SelfCE = dyn_cast<CastExpr>(E))
      CE = SelfCE;

  if (CE) {
    QualType DestTy = CE->getType();
    if (DestTy->isIntegerType()) {
      // Get the bit-width of the destination type.
      unsigned width = C.getASTContext().getTypeSize(DestTy);
      if (width >= 64)
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BOp, CheckerContext &C) const {
  // We are only interested in left shift operators.
  if (BOp->getOpcode() != BO_Shl)
    return;

  const Expr *LHS = BOp->getLHS();
  if (!LHS)
    return;

  // If the LHS expression is explicitly cast to a 64-bit integer, then no bug.
  if (isProperlyCastTo64(LHS, C))
    return;

  QualType LHSType = LHS->getType();
  // Proceed only if the LHS is an integer type.
  if (!LHSType->isIntegerType())
    return;

  unsigned typeWidth = C.getASTContext().getTypeSize(LHSType);
  // If the width is less than 64 bits, then shifting might lead to overflow.
  if (typeWidth >= 64)
    return;

  // Report a bug if a 32-bit (or sub-64-bit) integer is left-shifted without upcasting.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential integer overflow: left shift performed on a 32-bit value without upcasting to 64-bit", N);
  report->addRange(BOp->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects arithmetic shifts on 32-bit integers without prior upcasting to 64-bit",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```