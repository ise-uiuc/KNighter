#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
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

// Our checker subclass will only use the checkPreCall callback.
class SAGenTestChecker : public Checker< check::PreCall > { 
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Fixed-size copy without user length validation")) {}

  // Callback: Called before a function call is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // (Optional) Helper functions can be declared here if needed.
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression of this call.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Check if the call expression text contains "copy_from_sockptr".
  if (!ExprHasName(Origin, "copy_from_sockptr", C))
    return;

  // Retrieve the enclosing function declaration from the location context.
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;

  // We only report the bug if we're inside the buggy function.
  if (FD->getNameAsString() != "rfcomm_sock_setsockopt_old")
    return;

  // Cast the origin to a CallExpr to access its arguments.
  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return;

  // Ensure there are at least 3 arguments (destination, source, size).
  if (CE->getNumArgs() < 3)
    return;

  // Retrieve the third argument: the fixed size passed to copy_from_sockptr.
  const Expr *SizeArg = CE->getArg(2);
  llvm::APSInt EvalRes;
  // Attempt to evaluate the size argument.
  if (!EvaluateExprToInt(EvalRes, SizeArg, C))
    return;

  // We have a constant fixed size being passed in copy_from_sockptr,
  // and no prior validation that the user-supplied length (optlen) is sufficient.
  // Therefore, report a potential bug.

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "User length not validated for copy_from_sockptr", N);
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects fixed-size copy_from_sockptr usage without validating user-supplied optlen",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
