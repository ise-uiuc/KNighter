```cpp
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
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use memdup_array_user for array copy", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      bool isMulWithSizeof(const Expr *E, CheckerContext &C) const;
      bool looksLikeMulWithSizeofTextual(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::isMulWithSizeof(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  const Expr *NormE = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(NormE);
  if (!BO)
    return false;

  if (BO->getOpcode() != BO_Mul)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto IsSizeof = [](const Expr *Op) -> bool {
    if (!Op) return false;
    if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(Op)) {
      return U->getKind() == UETT_SizeOf;
    }
    return false;
  };

  return IsSizeof(LHS) || IsSizeof(RHS);
}

bool SAGenTestChecker::looksLikeMulWithSizeofTextual(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());

  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  if (Text.empty())
    return false;

  // Heuristic: both "sizeof" and "*" appear in the expression text.
  return Text.contains("sizeof") && Text.contains('*');
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Verify this is a call to memdup_user using source text matcher for robustness.
  if (!ExprHasName(OriginExpr, "memdup_user", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // Detect "count * sizeof(elem)" style usage.
  bool Match = isMulWithSizeof(SizeArg, C) || looksLikeMulWithSizeofTextual(SizeArg, C);
  if (!Match)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count * elem_size); multiplication may overflow.",
      N);
  R->addRange(SizeArg->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memdup_user used with count * sizeof(...) and suggests memdup_array_user",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
