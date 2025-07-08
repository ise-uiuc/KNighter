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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is required for this checker.

namespace {

/// Helper function to check if an expression contains a C-style cast
/// that casts an unsigned type (e.g. size_t) to a signed int.
static bool containsUnsignedToIntCast(const Expr *E) {
  if (!E)
    return false;

  // Use the utility function to search downward in the AST for a CStyleCastExpr.
  const CStyleCastExpr *Cast = findSpecificTypeInChildren<CStyleCastExpr>(E);
  if (!Cast)
    return false;

  // Check that the destination type of the cast is int.
  QualType DestTy = Cast->getType();
  if (!DestTy->isSpecificBuiltinType(BuiltinType::Int))
    return false;

  // Retrieve the subexpression being cast.
  const Expr *SubExpr = Cast->getSubExpr();
  if (!SubExpr)
    return false;

  QualType SubTy = SubExpr->getType();
  // Ensure the subexpression's type is an unsigned integer type.
  if (SubTy->isUnsignedIntegerType())
    return true;

  return false;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unsigned cast to int in check_add_overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C, const Expr *BadCastExpr) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // First, obtain the callee's identifier using the recommended approach.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Check if the call is to check_add_overflow.
  if (!ExprHasName(OriginExpr, "check_add_overflow", C))
    return;

  // Attempt to cast the call origin expression into a CallExpr.
  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE)
    return;

  // Iterate over the arguments of the call.
  for (unsigned i = 0, e = CE->getNumArgs(); i < e; ++i) {
    const Expr *Arg = CE->getArg(i);
    if (!Arg)
      continue;
    // Check if the argument contains a cast from unsigned to int.
    if (containsUnsignedToIntCast(Arg)) {
      reportBug(Call, C, Arg);
      // Report the bug only once per call.
      return;
    }
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C, const Expr *BadCastExpr) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create a bug report with a short, clear message.
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Casting unsigned to int in check_add_overflow may mask overflows", N);
  report->addRange(BadCastExpr->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects casting unsigned values to int in check_add_overflow calls that might mask overflows",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
