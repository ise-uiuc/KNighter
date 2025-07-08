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

// No additional program state maps are needed for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unbounded strcpy into fixed-size buffer")) {}

  // Callback for checking function call events.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Report a bug when an unbounded strcpy copies into a fixed-size destination.
  void reportBufferOverflow(const CallEvent &Call, CheckerContext &C, const Expr *DestExpr) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the original call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use the utility function to check if this call expression's text contains "strcpy".
  if (!ExprHasName(OriginExpr, "strcpy", C))
    return;
  
  // Check that the call has at least one argument.
  if (Call.getNumArgs() < 1)
    return;
  
  // Get the destination argument (first argument) of strcpy.
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;
  
  // Use utility function to get the fixed-size of the destination buffer.
  llvm::APInt ArraySize(32, 0);
  if (!getArraySizeFromExpr(ArraySize, DestExpr))
    return;
  
  // If getArraySizeFromExpr returned true, then the destination is a fixed-size array.
  // Report bug.
  reportBufferOverflow(Call, C, DestExpr);
}

void SAGenTestChecker::reportBufferOverflow(const CallEvent &Call, CheckerContext &C, const Expr *DestExpr) const {
  // Generate an error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  // Create a bug report with a short, clear message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unbounded strcpy may overflow fixed-size destination buffer", N);
  
  // Optionally add the source range of the destination argument.
  Report->addRange(DestExpr->getSourceRange());
  
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of strcpy that may overflow fixed-size buffers; consider using a bounded copy function",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```