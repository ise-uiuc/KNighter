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
#include "clang/Lex/Lexer.h" // Added for Lexer support if needed

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker inspects calls made to copy_from_sockptr, which is used
// to copy from a userspace pointer without validating the user-supplied length.
// This can lead to slab-out-of-bounds accesses.
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked User Input Length")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Obtain the origin expression of the call.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Check if the call is to "copy_from_sockptr".
  // Use the utility function to match the function name.
  if (!ExprHasName(Origin, "copy_from_sockptr", C))
    return;

  // Do not trigger a report if the function is "bt_copy_from_sockptr", which performs proper validation.
  if (ExprHasName(Origin, "bt_copy_from_sockptr", C))
    return;

  // Generate a bug report node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Emit a non-fatal error report with a brief, clear message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked user input length when copying from userspace", N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects usage of copy_from_sockptr without validating the user-supplied length", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
