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
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker< check::PreCall > { 
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker() 
     : BT(new BugType(this, "Buffer Overflow Risk", "Security")) {}

   // Callback: This function is invoked before each function call.
   void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
   // (No additional self-defined helper functions are needed for this checker.)
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Step 1: Detect a call to copy_from_user via the origin expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "copy_from_user", C))
    return;
  
  // Ensure the call has at least three arguments.
  if (Call.getNumArgs() < 3)
    return;

  // Step 2: Retrieve the destination argument (the first argument).
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;
  
  llvm::APInt ArraySize(32, 0);
  // Attempt to extract the size of the destination buffer from its declaration expression.
  if (!getArraySizeFromExpr(ArraySize, DestExpr))
    return;
  
  // When the array size is small, there is no point in further analysis.
  if (ArraySize.getLimitedValue() <= 1)
    return;
  
  // Step 3: Retrieve and evaluate the length argument (the third argument - index 2).
  const Expr *LengthExpr = Call.getArgExpr(2);
  if (!LengthExpr)
    return;
  
  llvm::APSInt NBytes;
  if (!EvaluateExprToInt(NBytes, LengthExpr, C))
    return;
  
  // Step 4: Compute maximum allowed copy size: destination size minus one.
  uint64_t MaxPermissibleCopy = ArraySize.getZExtValue() - 1;
  
  // Step 5: If the user-supplied length exceeds the maximum permissible copy size,
  // report a potential buffer overflow.
  if (NBytes.getLimitedValue() > MaxPermissibleCopy) {
    // Generate a non-fatal error node.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
      
    auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential buffer overflow: user-supplied length exceeds destination buffer capacity",
      N);
    Report->addRange(OriginExpr->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential buffer overflow in copy_from_user due to user-supplied length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```