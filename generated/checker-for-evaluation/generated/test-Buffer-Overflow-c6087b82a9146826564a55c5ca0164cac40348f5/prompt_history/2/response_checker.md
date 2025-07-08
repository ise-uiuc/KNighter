```cpp
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
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state maps are needed for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer overflow in copy_from_user")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report a bug.
  void reportBufferOverflow(const Expr *SizeExpr, CheckerContext &C) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Buffer overflow in copy_from_user: size exceeds destination capacity", N);
    report->addRange(SizeExpr->getSourceRange());
    C.emitReport(std::move(report));
  }
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Ensure we are analyzing a copy_from_user call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "copy_from_user", C))
    return;

  // Obtain the destination buffer expression (first argument).
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Get the size of the destination buffer.
  llvm::APInt ArraySize(32, 0);
  if (!getArraySizeFromExpr(ArraySize, DestExpr))
    return; // Cannot determine array size, so do not warn.

  // Compute the maximum allowed safe copy size: buffer size minus one.
  llvm::APInt AllowedSize = ArraySize;
  AllowedSize = AllowedSize - 1;

  // Obtain the third argument (nbytes) as the copy size.
  const Expr *NBytesExpr = Call.getArgExpr(2);
  if (!NBytesExpr)
    return;

  // If the expression text contains "min(", assume proper constraining is applied.
  if (ExprHasName(NBytesExpr, "min", C))
    return;

  llvm::APSInt EvalNBytes;
  if (!EvaluateExprToInt(EvalNBytes, NBytesExpr, C)) {
    // Could not evaluate the copy size; report a potential issue.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Potential buffer overflow in copy_from_user: unable to evaluate copy size", N);
    report->addRange(NBytesExpr->getSourceRange());
    C.emitReport(std::move(report));
    return;
  }

  // If the evaluated copy size is greater than the allowed safe size, report a bug.
  if (EvalNBytes > AllowedSize) {
    reportBufferOverflow(NBytesExpr, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects buffer overflow in copy_from_user when the copy size exceeds the destination capacity",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```