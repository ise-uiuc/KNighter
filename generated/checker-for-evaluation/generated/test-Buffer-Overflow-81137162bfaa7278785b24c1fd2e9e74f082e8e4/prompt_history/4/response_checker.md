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
#include "clang/Lex/Lexer.h"  // Additional include if needed

using namespace clang;
using namespace ento;
using namespace taint;

//
// This checker detects unsafe use of strcpy that may lead to buffer overflow,
// particularly when copying into a fixed-size buffer without bounds checking.
//

// No extra program state customization is necessary for this checker.

namespace {

class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unsafe strcpy usage")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // First, make sure this is a call to strcpy.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use the utility function for an accurate name check.
  if (!ExprHasName(OriginExpr, "strcpy", C))
    return;

  // Make sure we have exactly two arguments.
  if (Call.getNumArgs() < 2)
    return;

  // Retrieve the destination and source expressions.
  const Expr *DestExpr = Call.getArgExpr(0);
  const Expr *SrcExpr  = Call.getArgExpr(1);
  if (!DestExpr || !SrcExpr)
    return;

  // Attempt to obtain the size of the destination array.
  llvm::APInt DestArraySize(32, 0);
  if (!getArraySizeFromExpr(DestArraySize, DestExpr))
    return;  // Not a fixed-size array; nothing to check.

  // Attempt to get the size of the source string if it is a string literal.
  llvm::APInt SrcStringSize(32, 0);
  bool isStringLiteral = getStringSize(SrcStringSize, SrcExpr);
  if (!isStringLiteral)
    return;  // Missing information; do not report.

  // Compare the source string's length with the destination buffer size.
  uint64_t DestSize = DestArraySize.getZExtValue();
  uint64_t SrcSize  = SrcStringSize.getZExtValue();

  // Report a potential bug if the source string length is greater than or equal to
  // the fixed-size buffer. (We assume no room for the terminator if they are equal.)
  if (SrcSize >= DestSize) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Unsafe strcpy usage may lead to buffer overflow", N);
    Report->addRange(OriginExpr->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe strcpy usage that may overflow fixed-size buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```