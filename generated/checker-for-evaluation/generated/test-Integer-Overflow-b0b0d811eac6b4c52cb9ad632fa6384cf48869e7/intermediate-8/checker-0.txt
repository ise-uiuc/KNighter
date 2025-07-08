#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Lex/Lexer.h"

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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

/// Helper function to decide if a type is (or aliases) dma_addr_t.
/// For simplicity we check if the type's string representation contains "dma_addr_t".
static bool isDmaAddrType(QualType QT) {
  // Do not ignore qualifiers here; user-defined typedefs may still appear.
  llvm::StringRef TypeStr = QT.getAsString();
  return TypeStr.contains("dma_addr_t");
}

/// Checker that detects suspicious multiplication operations mixing dma_addr_t
/// with an integer type.
class SAGenTestChecker
    : public Checker< check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Suspicious Integer Multiplication",
    "Arithmetic")) {}

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

private:
  /// Reports the suspicious multiplication bug.
  void reportSuspiciousMultiplication(const BinaryOperator *BO, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  // We are only interested in multiplication operators.
  if (BO->getOpcode() != BO_Mul)
    return;

  // Retrieve the types of the left-hand side and right-hand side.
  QualType LHST = BO->getLHS()->getType();
  QualType RHST = BO->getRHS()->getType();

  // Check if one operand is dma_addr_t and the other is an integer type
  // that is not declared as dma_addr_t.
  bool LHSisDma = isDmaAddrType(LHST);
  bool RHSisDma = isDmaAddrType(RHST);

  // If neither operand is dma_addr_t, ignore.
  if (!LHSisDma && !RHSisDma)
    return;

  // Determine if mixing occurs:
  // One operand must be dma_addr_t and the other must be an integer.
  if (LHSisDma && RHST->isIntegerType() && !isDmaAddrType(RHST)) {
    reportSuspiciousMultiplication(BO, C);
    return;
  }
  if (RHSisDma && LHST->isIntegerType() && !isDmaAddrType(LHST)) {
    reportSuspiciousMultiplication(BO, C);
    return;
  }
}

void SAGenTestChecker::reportSuspiciousMultiplication(const BinaryOperator *BO, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create a short and clear bug report.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Suspicious multiplication mixing dma_addr_t with int may cause integer overflow",
      N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects arithmetic multiplications mixing dma_addr_t with int that might overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
