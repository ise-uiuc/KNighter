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

#include "clang/Lex/Lexer.h"  // For Lexer::getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker detects the use of strcpy to copy a string into a fixed-size
// buffer without checking for buffer overflow.
class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked strcpy", "Buffer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, const Expr *OriginExpr, CheckerContext &C) const;
};

void SAGenTestChecker::reportBug(const CallEvent &Call, const Expr *OriginExpr,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked strcpy on a fixed-size buffer may cause buffer overflow", N);
  report->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Obtain the original call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // We use ExprHasName to accurately verify that the call is to strcpy.
  if (!ExprHasName(OriginExpr, "strcpy", C))
    return;

  // Retrieve the destination expression: strcpy(dest, src)
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Try to retrieve the size of the destination buffer.
  llvm::APInt DestSize(32, 0);
  bool HasFixedSize = getArraySizeFromExpr(DestSize, DestExpr);
  if (!HasFixedSize)
    return; // Not a fixed-size array; do not report.

  // Retrieve the source expression.
  const Expr *SrcExpr = Call.getArgExpr(1);
  if (!SrcExpr)
    return;

  llvm::APInt SrcSize(32, 0);
  bool IsStringLiteral = getStringSize(SrcSize, SrcExpr);

  // Determine if there is a potential overflow risk:
  // If the source is a string literal and its length is greater than or equal
  // to the destination size then report an error.
  // If the source is not a literal, we conservatively report a potential bug.
  if (IsStringLiteral) {
    if (SrcSize.getLimitedValue() >= DestSize.getLimitedValue()) {
      reportBug(Call, OriginExpr, C);
    }
  }
  else {
    // When the source is not a string literal, we cannot decide safely the size;
    // therefore, warn about the unchecked use of strcpy on a fixed-size buffer.
    reportBug(Call, OriginExpr, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked strcpy calls on fixed-size buffers which may cause buffer overflows",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```