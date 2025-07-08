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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "User-supplied buffer length not validated")) {}

  // Callback to intercept calls.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) override;

private:
  // Helper: Determine whether the call occurs inside a setsockopt function.
  bool isInsideSetsockopt(const Expr *OriginExpr, CheckerContext &C) const {
    // Instead of using findSpecificTypeInParents, obtain the current function declaration
    // from the location context.
    const Decl *D = C.getLocationContext()->getDecl();
    const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
    if (!FD)
      return false;
    StringRef FuncName = FD->getName();
    // Check if the function name suggests a setsockopt handler.
    // Both "rfcomm_sock_setsockopt" and "rfcomm_sock_setsockopt_old" are relevant.
    return FuncName.contains("sock_setsockopt");
  }
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Only proceed if the call's source textual representation contains "copy_from_sockptr"
  // Use ExprHasName to correctly check the identifier.
  if (!ExprHasName(OriginExpr, "copy_from_sockptr", C))
    return;

  // Ensure we are inside a socket option setting function.
  if (!isInsideSetsockopt(OriginExpr, C))
    return;

  // At this point, we have detected a use of copy_from_sockptr (instead of bt_copy_from_sockptr)
  // within a setsockopt function. This indicates that the user-supplied buffer length may not
  // have been validated properly.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "User-supplied buffer length not validated (use bt_copy_from_sockptr instead)", N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of copy_from_sockptr in setsockopt functions without validating user-supplied length", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
