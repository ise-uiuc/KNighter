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
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No additional program state maps are needed for this checker.

namespace {

class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked byte count in copy_from_user")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBufferOverflow(const CallEvent &Call, CheckerContext &C, 
                            uint64_t BufferCapacity, uint64_t nbytes) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Check if the current call is to copy_from_user.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin || !ExprHasName(Origin, "copy_from_user", C))
    return;

  // Retrieve the destination argument (first parameter).
  const Expr *DestExpr = Call.getArgExpr(0);
  llvm::APInt ArraySize(32, 0);
  // Try to extract the fixed array size from the destination expression.
  if (!getArraySizeFromExpr(ArraySize, DestExpr))
    return; // Could not determine a constant array size

  // Compute effective capacity: (ArraySize - 1) to account for a null terminator.
  llvm::APInt EffectiveCapacity = ArraySize - 1;

  // Retrieve nbytes from the third argument.
  const Expr *NBytesExpr = Call.getArgExpr(2);
  llvm::APSInt EvaluatedNBytes(32);
  if (!EvaluateExprToInt(EvaluatedNBytes, NBytesExpr, C))
    return; // nbytes cannot be evaluated

  // Convert EffectiveCapacity to an APSInt for comparison.
  llvm::APSInt Capacity(EvaluatedNBytes.getBitWidth(), false);
  Capacity = EffectiveCapacity;

  // Compare the user-provided byte count with the effective capacity.
  if (EvaluatedNBytes > Capacity) {
    // Report a potential buffer overflow bug.
    reportBufferOverflow(Call, C, Capacity.getLimitedValue(), EvaluatedNBytes.getLimitedValue());
  }
}

void SAGenTestChecker::reportBufferOverflow(const CallEvent &Call, CheckerContext &C,
                                              uint64_t BufferCapacity, uint64_t nbytes) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  // Create a concise bug report message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked user-provided byte count may overflow fixed buffer", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked user-provided byte count in copy_from_user that may overflow a fixed buffer", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
