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

// Additional includes for AST analysis.
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Define the constant for TRANSFER_FUNC_POINTS. In the patch, this should match
// the value used in the driver. For our analysis, we assume it is 1024.
static const int TRANSFER_FUNC_POINTS = 1024;

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked Array Index", "Bounds Checking")) {}

  // Callback for array subscript expressions.
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

private:
  // Helper: Check if a nearby branch condition in the parent chain serves as a bounds guard.
  // We scan upward for an IfStmt whose condition text contains "TRANSFER_FUNC_POINTS".
  bool hasBoundsCheckInParents(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::hasBoundsCheckInParents(const Expr *E, CheckerContext &C) const {
  // Look upward in the AST for an IfStmt.
  // Use the provided utility function "findSpecificTypeInParents".
  if (const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(E, C)) {
    const Expr *Cond = IfS->getCond();
    if (Cond && ExprHasName(Cond, "TRANSFER_FUNC_POINTS", C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  // We are only interested in array accesses on structures that contain "tf_pts".
  // Get the base expression of the subscript.
  const Expr *BaseExpr = ASE->getBase();
  if (!BaseExpr)
    return;

  // Check if the source text of the base expression contains "tf_pts".
  // This will cover tf_pts.red, tf_pts.green or tf_pts.blue.
  if (!ExprHasName(BaseExpr, "tf_pts", C))
    return;

  // Retrieve the index expression.
  const Expr *IdxExpr = ASE->getIdx();
  if (!IdxExpr)
    return;

  // Evaluate the index expression to an integer if possible.
  llvm::APSInt IndexVal;
  if (!EvaluateExprToInt(IndexVal, IdxExpr, C))
    return;

  // If the index is less than TRANSFER_FUNC_POINTS, then no problem.
  if (IndexVal.getSExtValue() < TRANSFER_FUNC_POINTS)
    return;

  // Check whether there is a bounds check in a nearby branch condition.
  if (hasBoundsCheckInParents(ASE, C))
    return; // The index access is guarded.

  // Otherwise, report potential out-of-bound array access.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked array index may exceed TRANSFER_FUNC_POINTS", N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects array accesses on transfer function points that may be out-of-bounds",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
