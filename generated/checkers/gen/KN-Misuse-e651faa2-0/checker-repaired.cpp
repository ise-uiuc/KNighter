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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe user array duplication size", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      bool isManualArrayByteCalc(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::isManualArrayByteCalc(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  const Expr *IE = E->IgnoreParenImpCasts();

  // Pattern 1: explicit use of array_size(...)
  if (ExprHasName(IE, "array_size", C))
    return true;

  // Pattern 2: count * sizeof(T) or sizeof(T) * count
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(IE);
  if (!BO) {
    // Search downwards for a multiplication if the immediate node isn't a BO
    BO = findSpecificTypeInChildren<BinaryOperator>(IE);
  }

  if (BO && BO->getOpcode() == BO_Mul) {
    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

    const auto *UL = dyn_cast<UnaryExprOrTypeTraitExpr>(L);
    const auto *UR = dyn_cast<UnaryExprOrTypeTraitExpr>(R);

    if ((UL && UL->getKind() == UETT_SizeOf) ||
        (UR && UR->getKind() == UETT_SizeOf)) {
      return true;
    }
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Only consider the legacy two-argument functions.
  if (Call.getNumArgs() < 2)
    return;

  bool IsMemdupUser = ExprHasName(Origin, "memdup_user", C) && Call.getNumArgs() == 2;
  bool IsVmemdupUser = ExprHasName(Origin, "vmemdup_user", C) && Call.getNumArgs() == 2;

  if (!IsMemdupUser && !IsVmemdupUser)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  if (!isManualArrayByteCalc(SizeArg, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  const char *Msg = IsVmemdupUser
                      ? "Use vmemdup_array_user() instead of manual size multiplication or array_size(); avoids overflow."
                      : "Use memdup_array_user() instead of manual size multiplication; avoids overflow.";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(SizeArg->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects manual size calculations passed to memdup_user/vmemdup_user; suggest *_array_user variants",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
