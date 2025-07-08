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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Fixed size copy without validation")) {}

  // Callback: Pre-visit a call event.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    // Retrieve the original call expression to perform a reliable name check.
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;

    // Only flag calls to "copy_from_sockptr".
    if (!ExprHasName(OriginExpr, "copy_from_sockptr", C))
      return;

    // Report an error node as a non-fatal warning.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    // Emit a bug report with a short message.
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "User input length not validated before copying – potential slab buffer over-read", N);
    C.emitReport(std::move(Report));
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of copy_from_sockptr without validating the input length, "
      "which can lead to slab buffer over-read",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
