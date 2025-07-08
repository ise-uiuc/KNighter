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

// Additional includes if needed
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No additional program state customization is needed for this checker.

namespace {

class SAGenTestChecker : public Checker< check::PreCall > { 
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unbounded strcpy on fixed-size buffer")) {}

  // Callback function: intercept call events.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to generate a bug report.
  void reportBug(const CallEvent &Call, const Expr *DestExpr, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the originating call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if the called function is named "strcpy".
  if (!ExprHasName(OriginExpr, "strcpy", C))
    return;

  // Ensure strcpy has at least 2 arguments: strcpy(dest, src)
  if (Call.getNumArgs() < 2)
    return;

  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Use utility function to check if the destination expression is a fixed-size array.
  llvm::APInt ArraySize(32, 0);
  if (getArraySizeFromExpr(ArraySize, DestExpr)) {
    // Report bug since an unbounded strcpy on a fixed-size array may overflow.
    reportBug(Call, DestExpr, C);
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call, const Expr *DestExpr, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unbounded strcpy on fixed-size buffer may overflow", N);
  report->addRange(DestExpr->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of strcpy on a fixed-size buffer, which may lead to buffer overflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```