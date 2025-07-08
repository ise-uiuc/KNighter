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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No additional program state is needed for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unsafe use of strcpy")) {}

  // We use checkPreCall to intercept all function call events.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportBug(CheckerContext &C, const CallEvent &Call, const Expr *OriginExpr) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression for the call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use utility function to check if the function call expression contains "strcpy"
  if (!ExprHasName(OriginExpr, "strcpy", C))
    return;

  // Ensure there are at least two arguments.
  if (Call.getNumArgs() < 2)
    return;

  // Retrieve the destination and source arguments.
  const Expr *DestExpr = dyn_cast_or_null<Expr>(Call.getArgExpr(0));
  const Expr *SrcExpr  = dyn_cast_or_null<Expr>(Call.getArgExpr(1));
  if (!DestExpr || !SrcExpr)
    return;

  // Attempt to get the size of the destination array.
  llvm::APInt DestSize(/*BitWidth=*/32, 0);
  if (!getArraySizeFromExpr(DestSize, DestExpr))
    return; // Not a fixed-size array; skip further checking.

  bool reportWarning = false;

  // Attempt to get the size of the source string.
  llvm::APInt SrcSize(/*BitWidth=*/32, 0);
  if (getStringSize(SrcSize, SrcExpr)) {
    // Compare the source string size with the fixed array size.
    // If the source string length is greater than or equal to the destination
    // size, a buffer overflow may occur.
    if (SrcSize.uge(DestSize))
      reportWarning = true;
  } else {
    // If we cannot determine the source size, be conservative and report a warning.
    reportWarning = true;
  }

  if (reportWarning)
    reportBug(C, Call, OriginExpr);
}

void SAGenTestChecker::reportBug(CheckerContext &C, const CallEvent &Call,
                                 const Expr *OriginExpr) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create and emit a bug report.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unsafe use of strcpy may cause buffer overflow", N);
  Report->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe use of strcpy which may lead to fixed buffer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
