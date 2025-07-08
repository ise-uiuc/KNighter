#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"  // Removed the missing "clang/StaticAnalyzer/Checkers/Checkers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
// Removed the include for "clang/StaticAnalyzer/Core/PathSensitive/SVal.h" because it does not exist in Clang-18.
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/APInt.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No additional custom program states are needed for this checker

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer Overflow Risk", "Security")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the origin expression to check for "copy_from_user".
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "copy_from_user", C))
    return;

  // Retrieve the destination pointer argument (first argument)
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Attempt to retrieve the destination array size.
  llvm::APInt DestArraySize(32, 0);
  if (!getArraySizeFromExpr(DestArraySize, DestExpr))
    return; // Not a constant sized array, skip reporting

  // Retrieve the number of bytes argument (third argument)
  const Expr *NBytesExpr = Call.getArgExpr(2);
  if (!NBytesExpr)
    return;

  llvm::APSInt NBytesVal(32);
  if (!EvaluateExprToInt(NBytesVal, NBytesExpr, C))
    return; // Could not evaluate the nbytes argument

  // Compare the evaluated nbytes with the destination buffer size.
  // Note: For safety, we assume that the full buffer size is available;
  // if the code subtracts one or applies min(), that logic is not modeled here.
  uint64_t DestSize = DestArraySize.getZExtValue();
  uint64_t RequestedBytes = NBytesVal.getZExtValue();

  if (RequestedBytes > DestSize) {
    // Potential bug: copy_from_user is copying more bytes than the destination buffer can hold.
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Buffer overflow risk: copy_from_user copies more bytes than the destination buffer size", ErrNode);
    Report->addRange(OriginExpr->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential buffer overflow when copy_from_user copies more data than a fixed destination buffer can hold",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
