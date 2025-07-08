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
#include "clang/AST/Expr.h"  // Use the correct header for CStyleCastExpr in Clang-18.
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// The checker detects when an unsigned value is explicitly cast to int in a
// call to check_add_overflow, which may bypass proper overflow detection.
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Unsigned to int cast in check_add_overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the origin expression for an accurate function name check.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Only consider calls to check_add_overflow.
  if (!ExprHasName(OriginExpr, "check_add_overflow", C))
    return;

  // Check the first two arguments (the summands).
  for (unsigned i = 0; i < 2; ++i) {
    if (i >= Call.getNumArgs())
      continue;

    const Expr *ArgExpr = Call.getArgExpr(i);
    if (!ArgExpr)
      continue;

    // Look through parentheses and implicit casts.
    const Expr *StrippedArg = ArgExpr->IgnoreParenImpCasts();

    // Check if the argument is an explicit C-style cast.
    const CStyleCastExpr *CastExpr = dyn_cast<CStyleCastExpr>(StrippedArg);
    if (!CastExpr)
      continue;

    // Verify the cast target type is 'int'.
    QualType TargetType = CastExpr->getType();
    if (!TargetType->isSpecificBuiltinType(BuiltinType::Int))
      continue;

    // Check if the sub-expression's type is an unsigned integer type.
    QualType SubExprType = CastExpr->getSubExpr()->getType();
    if (SubExprType->isUnsignedIntegerType()) {
      // Found a cast from an unsigned type to int in check_add_overflow.
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Casting unsigned value to int in check_add_overflow bypasses proper overflow detection", N);
      Report->addRange(ArgExpr->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects casting unsigned value to int in check_add_overflow "
      "which bypasses proper overflow detection", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
