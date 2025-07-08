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

#include "clang/AST/Decl.h"
// Removed erroneous header: #include "clang/AST/FunctionDecl.h"
// Removed erroneous header: #include "clang/StaticAnalyzer/Core/PathSensitive/StackFrameContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// This checker does not require custom program state.
// It simply detects calls to copy_from_sockptr in functions which are
// expected to validate user input length (e.g., rfcomm_sock_setsockopt and
// rfcomm_sock_setsockopt_old).

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "User Input Length Validation Bug")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the call's origin expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if this call is to "copy_from_sockptr".
  // We use the utility function ExprHasName for an accurate check.
  if (!ExprHasName(OriginExpr, "copy_from_sockptr", C))
    return;

  // Optionally, narrow down to the vulnerable functions.
  // Get the current function context.
  const LocationContext *LCtx = C.getLocationContext();
  if (const Decl *D = LCtx->getDecl()) {
    if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
      StringRef FuncName = FD->getName();
      if (!(FuncName == "rfcomm_sock_setsockopt" || FuncName == "rfcomm_sock_setsockopt_old"))
        return;
    }
  }

  // Report the bug: using copy_from_sockptr without proper length validation.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "User input length not validated when copying data from user space", N);
  Report->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of copy_from_sockptr without validating user-supplied input length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
