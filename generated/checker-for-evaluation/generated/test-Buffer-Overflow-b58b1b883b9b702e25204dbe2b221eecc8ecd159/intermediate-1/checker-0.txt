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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No additional program state maps are needed for this checker.

namespace {

// This checker detects an unchecked subtraction on iter->count that
// can underflow if the shorten value is not less than iter->count.
class SAGenTestChecker 
  : public Checker< check::PreStmt<CompoundAssignOperator> > {
  
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked subtraction underflow")) {}

  // Callback for compound assignment operators (like "-=").
  void checkPreStmt(const CompoundAssignOperator *CA, CheckerContext &C) const;
  
private:
  // Helper function to report a bug.
  void reportUnderflow(const CompoundAssignOperator *CA, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const CompoundAssignOperator *CA,
                                      CheckerContext &C) const {
  // Check if the operator is subtraction assignment.
  if (CA->getOpcode() != BO_SubAssign)
    return;
    
  // Check if the left-hand side expression contains "iter->count".
  // This reduces false positives by focusing on our target field.
  const Expr *LHS = CA->getLHS();
  if (!LHS || !ExprHasName(LHS, "iter->count", C))
    return;
    
  // Try to evaluate the left-hand side (the current iter->count value)
  // and the right-hand side (the computed "shorten" value) into integer constants.
  llvm::APSInt LHSVal, RHSVal;
  bool IsLHSConst = EvaluateExprToInt(LHSVal, LHS, C);
  bool IsRHSConst = EvaluateExprToInt(RHSVal, CA->getRHS(), C);
  
  // If both are constant, check for a possible underflow.
  // Underflow occurs if the subtraction subtracts a value greater than or equal to iter->count.
  if (IsLHSConst && IsRHSConst) {
    if (RHSVal >= LHSVal) {
      reportUnderflow(CA, C);
    }
  }
  // If not evaluable, we do not report a bug due to lack of precise value information.
}

void SAGenTestChecker::reportUnderflow(const CompoundAssignOperator *CA,
                                         CheckerContext &C) const {
  // Generate a non-fatal error node as we are reporting a potential bug.
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;
    
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential underflow in iter->count subtraction (shorten >= iter->count)", ErrNode);
  Report->addRange(CA->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked arithmetic subtraction on iter->count that may underflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
