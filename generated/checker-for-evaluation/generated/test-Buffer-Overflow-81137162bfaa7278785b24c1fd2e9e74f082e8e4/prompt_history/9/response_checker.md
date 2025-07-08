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
#include "clang/Lex/Lexer.h" // For Lexer::getSourceText if needed

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is necessary for this checker.

namespace {

class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unsafe String Copy", "Security")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // (Optional) self-defined helper functions can be declared here if needed.
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Use utility function for accurate function name check.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "strcpy", C))
    return;

  // Ensure that strcpy has at least two arguments.
  if (Call.getNumArgs() < 2)
    return;

  // Retrieve the destination expression (first argument).
  const Expr *DstExpr = Call.getArgExpr(0);
  if (!DstExpr)
    return;

  // Get the memory region corresponding to the destination.
  const MemRegion *MR = getMemRegionFromExpr(DstExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Check if destination is a fixed-size array.
  llvm::APInt ArraySize(32, 0);
  if (getArraySizeFromExpr(ArraySize, DstExpr)) {
    // Fixed-size array detected, report potential overflow via unsafe strcpy.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Unsafe strcpy detected: potential buffer overflow", N);
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe use of strcpy that can lead to a fixed-size buffer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```