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
#include "clang/Lex/Lexer.h"  // For getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state maps are needed for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Fixed Buffer Overflow",
                                         "Security")) {}

  // Callback for intercepting calls.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Report a bug for potential buffer overflow.
  void reportBufferOverflow(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::reportBufferOverflow(const CallEvent &Call,
                                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer overflow in copy_from_user: user copy size exceeds fixed buffer size", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the original call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use ExprHasName for accurate checking: we are interested in copy_from_user.
  if (!ExprHasName(OriginExpr, "copy_from_user", C))
    return;
  
  // We expect at least three arguments: destination, source and size.
  if (Call.getNumArgs() < 3)
    return;
  
  // Extract the destination buffer argument.
  // This is assumed to be a fixed sized array.
  const Expr *DestExpr = Call.getArgExpr(0);
  llvm::APInt ArraySize(/*NumBits=*/32, 0);
  bool HasFixedSize = getArraySizeFromExpr(ArraySize, DestExpr);
  if (!HasFixedSize)
    return; // Not a fixed sized destination.
  
  // Extract the third argument which corresponds to the size to copy.
  const Expr *CopySizeExpr = Call.getArgExpr(2);
  
  llvm::APSInt CopySizeVal(/*NumBits=*/32, /*isUnsigned=*/true);
  if (EvaluateExprToInt(CopySizeVal, CopySizeExpr, C)) {
    // The buffer is zero terminated in the original code.
    // So the available space is fixed size minus one.
    if (CopySizeVal.getLimitedValue() > (ArraySize.getLimitedValue() - 1))
      reportBufferOverflow(Call, C);
  } else {
    // If we can't evaluate it to a constant, check the source text.
    // A min() call may indicate proper bounds checking.
    if (!ExprHasName(CopySizeExpr, "min", C))
      reportBufferOverflow(Call, C);
  }
  
  return;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential buffer overflow in copy_from_user by user copy size exceeding "
      "the fixed destination buffer size", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
