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

using namespace clang;
using namespace ento;
using namespace taint;

// Define a constant for the maximum number of transfer function points.
// Based on the bug patch, this value should match TRANSFER_FUNC_POINTS.
static const int TRANSFER_FUNC_POINTS = 1024;

namespace {

/// The checker detects array index accesses that may be out-of-bound
/// with respect to a fixed maximum number of elements (TRANSFER_FUNC_POINTS).
class SAGenTestChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Out-of-bound array index access")) {}

  /// Invoked when a memory location is loaded from or stored to.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  /// Reports an out-of-bound index access at statement S with the given index.
  void reportOutOfBounds(const Stmt *S, int Index, CheckerContext &C) const;
};

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // We only want to check array accesses, so we try to retrieve an ArraySubscriptExpr
  // from the current statement S or one of its parents.
  const auto *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(S, C);
  if (!ASE)
    return;

  // Get the index expression from the array subscript.
  const Expr *IndexExpr = ASE->getIdx();
  if (!IndexExpr)
    return;

  llvm::APSInt EvalRes;
  // Evaluate the index expression as an integer.
  if (!EvaluateExprToInt(EvalRes, IndexExpr, C))
    return;

  // Compare the evaluated index value against TRANSFER_FUNC_POINTS.
  if (EvalRes.getSExtValue() >= TRANSFER_FUNC_POINTS) {
    reportOutOfBounds(S, EvalRes.getSExtValue(), C);
  }
}

void SAGenTestChecker::reportOutOfBounds(const Stmt *S, int Index, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create an error message that is short and clear.
  llvm::SmallString<128> Msg;
  llvm::raw_svector_ostream OS(Msg);
  OS << "Out-of-bound array index access: index (" << Index
     << ") >= TRANSFER_FUNC_POINTS (" << TRANSFER_FUNC_POINTS << ")";

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, OS.str(), N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects insufficient index bounds checking before accessing fixed-size arrays", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
