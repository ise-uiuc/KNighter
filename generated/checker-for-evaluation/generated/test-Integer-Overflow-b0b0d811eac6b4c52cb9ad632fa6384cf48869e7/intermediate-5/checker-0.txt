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
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker intercepts multiplication operations (BinaryOperator '*')
// and checks if the two operands have different types (for instance,
// one operand being a dma_addr_t and the other a narrower integer type)
// which may lead to an unintentional integer overflow.
class SAGenTestChecker : public Checker< check::PreStmt<BinaryOperator> > { 
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unsafe multiplication of mixed types")) {}

  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;

private:
  // Returns true if the multiplication involves operands of different types
  // and one of them is dma_addr_t (as a substring in the type name).
  bool isTypeUnsafe(const QualType &LHS, const QualType &RHS) const;
};

bool SAGenTestChecker::isTypeUnsafe(const QualType &LHS, const QualType &RHS) const {
  // Obtain the canonical types to remove typedefs and other sugar.
  QualType lhsCanonical = LHS.getCanonicalType();
  QualType rhsCanonical = RHS.getCanonicalType();

  std::string lhsStr = lhsCanonical.getAsString();
  std::string rhsStr = rhsCanonical.getAsString();

  // If the types are identical, consider it safe.
  if (lhsStr == rhsStr)
    return false;

  // Check if either operand is (or involves) dma_addr_t.
  bool lhsIsDma = (lhsStr.find("dma_addr_t") != std::string::npos);
  bool rhsIsDma = (rhsStr.find("dma_addr_t") != std::string::npos);

  // If one of the operands is dma_addr_t and the types differ,
  // then this multiplication might be unsafe.
  if (lhsIsDma || rhsIsDma)
    return true;

  return false;
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *B, CheckerContext &C) const {
  // Only process multiplication operators.
  if (B->getOpcode() != BO_Mul)
    return;

  const Expr *LHS = B->getLHS()->IgnoreParenCasts();
  const Expr *RHS = B->getRHS()->IgnoreParenCasts();
  if (!LHS || !RHS)
    return;

  QualType lhsType = LHS->getType();
  QualType rhsType = RHS->getType();

  // If the types involved are not unsafe, then do nothing.
  if (!isTypeUnsafe(lhsType, rhsType))
    return;

  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Report the potential bug.
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unsafe multiplication with mixed types may cause integer overflow", N);
  report->addRange(B->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unsafe multiplication with mixed types that may cause integer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
