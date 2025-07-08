#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
// Removed the Taint.h include as it is not needed for this checker.
//#include "clang/StaticAnalyzer/Checkers/Taint.h"
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
#include <string>
#include <memory>

using namespace clang;
using namespace ento;

namespace {
// Register the checkPreStmt callback for BinaryOperator statements.
class SAGenTestChecker : public Checker< check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Multiplication Type Mismatch", "Custom Checker")) {}

  // Callback for every BinaryOperator statement.
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

private:
  // Helper function to decide if the two operand types are mismatched
  // i.e., one is dma_addr_t and the other is int (or contains "int").
  bool isMismatchedMul(const Expr *LHS, const Expr *RHS, CheckerContext &C) const;
};

bool SAGenTestChecker::isMismatchedMul(const Expr *LHS, const Expr *RHS,
                                         CheckerContext &C) const {
  // Get the QualTypes of LHS and RHS.
  QualType LType = LHS->getType();
  QualType RType = RHS->getType();

  // Get the string representations of the types.
  std::string LTypeStr = LType.getAsString(C.getASTContext().getLangOpts());
  std::string RTypeStr = RType.getAsString(C.getASTContext().getLangOpts());

  // We check if one operand is of type "dma_addr_t" and the other contains "int".
  bool LIsDma = (LTypeStr.find("dma_addr_t") != std::string::npos);
  bool RIsDma = (RTypeStr.find("dma_addr_t") != std::string::npos);
  bool LIsInt = (LTypeStr.find("int") != std::string::npos);
  bool RIsInt = (RTypeStr.find("int") != std::string::npos);

  // If one operand is dma_addr_t and the other is int (or an integer type), then we flag it.
  return ((LIsDma && RIsInt) || (RIsDma && LIsInt));
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  // Only interested in multiplication operations.
  if (BO->getOpcode() != BO_Mul)
    return;

  // Get the left-hand side and right-hand side operands.
  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // If the multiplication involves operands of mismatched types,
  // e.g. one is dma_addr_t and the other is int, report a warning.
  if (isMismatchedMul(LHS, RHS, C)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    // Using the approved API for bug reports.
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Multiplying operands of different types may lead to overflow", N);
    report->addRange(BO->getSourceRange());
    C.emitReport(std::move(report));
  }
}
  
} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects multiplication of operands of mismatched types (e.g. dma_addr_t and int) that may lead to overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
