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
#include "clang/AST/Expr.h" // Needed for ArraySubscriptExpr

using namespace clang;
using namespace ento;
using namespace taint;

// For the purpose of this checker, assume TRANSFER_FUNC_POINTS is defined as 1024.
static const int TRANSFER_FUNC_POINTS = 1024;

namespace {

class SAGenTestChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked Array Indexing",
                     "Potential out-of-bounds access on transfer function points array")) {}

  // Callback to check for potential unchecked array indexing.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportOutOfBound(const Expr *IdxExpr, int64_t Val, CheckerContext &C) const;
};

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only consider statements that exist.
  if (!S)
    return;

  // Use utility function to search downward in the AST for an ArraySubscriptExpr.
  const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S);
  if (!ASE)
    return;

  // Check underlying base expression's source text for "tf_pts" (indicating transfer function points)
  const Expr *BaseExpr = ASE->getBase();
  if (!BaseExpr || !ExprHasName(BaseExpr, "tf_pts", C))
    return;

  // Extract the subscript (index) expression.
  const Expr *IdxExpr = ASE->getIdx();
  if (!IdxExpr)
    return;

  // Attempt to evaluate the index expression to a constant integer.
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, IdxExpr, C))
    return; // Could not determine constant index value.

  // If the index is greater than or equal to TRANSFER_FUNC_POINTS, report a bug.
  if (EvalRes.getExtValue() >= TRANSFER_FUNC_POINTS) {
    reportOutOfBound(IdxExpr, EvalRes.getExtValue(), C);
  }
}

void SAGenTestChecker::reportOutOfBound(const Expr *IdxExpr, int64_t Val, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  // Create a short descriptive error message.
  SmallString<256> Buf;
  llvm::raw_svector_ostream OS(Buf);
  OS << "Unchecked array indexing: index value (" << Val
     << ") may exceed TRANSFER_FUNC_POINTS (" << TRANSFER_FUNC_POINTS << ")";
  
  // Create and emit the bug report.
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, OS.str(), N);
  Report->addRange(IdxExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked array indexing on transfer function points that may cause buffer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
