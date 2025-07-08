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
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed for this checker

namespace {

class SAGenTestChecker 
  : public Checker< check::PreStmt<ArraySubscriptExpr> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Buffer overflow", "Loop/Array Access")) {}

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

private:
  // Helper function to report the bug at the location of the array subscript
  void reportBufferOverflow(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  // Check if the base expression of the array access corresponds to "DcfClocks".
  const Expr *BaseExpr = ASE->getBase()->IgnoreImplicit();
  if (!BaseExpr)
    return;

  // Use utility function to see if the expression text contains "DcfClocks".
  if (!ExprHasName(BaseExpr, "DcfClocks", C))
    return;

  // Now, climb the AST to find the enclosing ForStmt.
  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(ASE, C);
  if (!FS)
    return;

  // In the ForStmt, check the loop condition.
  const Expr *Cond = FS->getCond();
  if (!Cond)
    return;

  // We check if the condition expression contains "VG_NUM_SOC_VOLTAGE_LEVELS".
  if (!ExprHasName(Cond, "VG_NUM_SOC_VOLTAGE_LEVELS", C))
    return;

  // Also optionally, check that the condition does not have a safeguard
  // against accessing past the array size by looking for "VG_NUM_DCFCLK_DPM_LEVELS".
  if (ExprHasName(Cond, "VG_NUM_DCFCLK_DPM_LEVELS", C))
    return;

  // If we get here, then we likely have a loop iterating using VG_NUM_SOC_VOLTAGE_LEVELS
  // and an array access on "DcfClocks" that is supposed to use VG_NUM_DCFCLK_DPM_LEVELS.
  reportBufferOverflow(ASE, C);
}

void SAGenTestChecker::reportBufferOverflow(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer overflow: Loop iterates beyond the boundary of DcfClocks array", N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects buffer overflow when a loop iterates using VG_NUM_SOC_VOLTAGE_LEVELS to index into DcfClocks", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
