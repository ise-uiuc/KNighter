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
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Unsafe use of strcpy", "Buffer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression and check if it is a call to strcpy.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "strcpy", C))
    return;

  // Check that there are at least two arguments.
  if (Call.getNumArgs() < 2)
    return;

  // Retrieve the destination argument (first parameter).
  const Expr *DestExpr = Call.getArgExpr(0);
  llvm::APInt ArraySize(32, 0);
  // Use the utility function to see if the destination is a fixed-size array.
  if (!getArraySizeFromExpr(ArraySize, DestExpr))
    return;  // Not a fixed-size array; nothing to do.

  // At this point, we know that strcpy is used with a fixed-size destination buffer.
  // This is unsafe as strcpy does not perform bounds checking.

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto BugReport = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unsafe use of strcpy on fixed-size buffer may lead to buffer overflow", N);
  BugReport->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(BugReport));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unsafe use of strcpy on fixed-size buffers which may lead to buffer overflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
