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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Unchecked copy_from_user size")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the origin expression to verify we are handling a 'copy_from_user' call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "copy_from_user", C))
    return;

  // Ensure the call has at least three arguments.
  if (Call.getNumArgs() < 3)
    return;

  // Retrieve the third argument: nbytes to copy.
  const Expr *NbytesExpr = dyn_cast_or_null<Expr>(Call.getArgExpr(2));
  if (!NbytesExpr)
    return;
  
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, NbytesExpr, C))
    return;
  
  // Get the value of nbytes.
  int nbytesVal = EvalRes.getSExtValue();

  // Retrieve the destination buffer expression (first argument).
  const Expr *DestExpr = dyn_cast_or_null<Expr>(Call.getArgExpr(0));
  if (!DestExpr)
    return;
  
  // Try to obtain the array size from the destination expression.
  llvm::APInt arraySize;
  if (!getArraySizeFromExpr(arraySize, DestExpr))
    return; // Destination is not a constant-sized array.

  // Assume the fixed-size buffer reserves one byte for a terminator.
  uint64_t capacity = arraySize.getZExtValue();
  if (capacity == 0)
    return;
  uint64_t maxSafeCopy = capacity - 1;

  // Compare the evaluated nbytes with the safe copy size.
  if (static_cast<uint64_t>(nbytesVal) > maxSafeCopy) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "copy_from_user copies more bytes than destination buffer capacity", N);
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects copy_from_user copying more bytes than a fixed-size destination buffer can hold", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```