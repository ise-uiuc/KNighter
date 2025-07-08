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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// The checker only needs the checkPreCall callback.
class SAGenTestChecker : public Checker<check::PreCall> { 
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Legacy copy_from_sockptr misuse")) {}

  // Callback to check call events.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper to report a bug.
  void reportBug(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
};

void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // We only care about calls to copy_from_sockptr.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use ExprHasName for accurate name matching.
  if (!ExprHasName(OriginExpr, "copy_from_sockptr", C))
    return;

  unsigned NumArgs = Call.getNumArgs();

  // Legacy usage: exactly three arguments means no user-supplied length check.
  if (NumArgs == 3) {
    reportBug(Call, C, "Unchecked copy_from_sockptr call: potential out-of-bounds read");
    return;
  }
  // For calls with four or more arguments, compare expected copy size and user length.
  else if (NumArgs >= 4) {
    llvm::APSInt ExpectedSize, UserLen;
    // In the patch the expected copy size is passed as the second argument (index 1).
    // The user provided length is passed as the fourth argument (index 3).
    const Expr *ExpectedExpr = Call.getArgExpr(1);
    const Expr *UserLenExpr = Call.getArgExpr(3);
    bool EvalExpected = EvaluateExprToInt(ExpectedSize, ExpectedExpr, C);
    bool EvalUserLen = EvaluateExprToInt(UserLen, UserLenExpr, C);
    if (EvalExpected && EvalUserLen) {
      if (ExpectedSize.getExtValue() > UserLen.getExtValue()) {
        reportBug(Call, C, "User-supplied length insufficient for copy_from_sockptr");
      }
    }
    // If we cannot determine the sizes, do not report a bug.
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of legacy copy_from_sockptr without proper user length validation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
