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

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use memdup_array_user for array copy",
                       "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Check if expression (ignoring parens/imp-casts) is a sizeof(...) expr.
  static bool isSizeofExpr(const Expr *E);

  // Return true if E (ignoring parens/imp-casts) is exactly a multiply
  // with exactly one side being a sizeof(...). If so, returns that BO via Out.
  static bool isTopLevelMulWithExactlyOneSizeof(const Expr *E,
                                                const BinaryOperator *&Out);

  // Filter out benign cases (e.g., plain sizeof(...) without multiplication).
  static bool isFalsePositive(const Expr *SizeArg);

  // Recognize memdup_user (not memdup_user_nul etc.).
  static bool isMemdupUser(const CallEvent &Call);
};

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E))
    return U->getKind() == UETT_SizeOf;
  return false;
}

bool SAGenTestChecker::isTopLevelMulWithExactlyOneSizeof(
    const Expr *E, const BinaryOperator *&Out) {
  Out = nullptr;
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return false;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  bool LIsSizeof = isSizeofExpr(LHS);
  bool RIsSizeof = isSizeofExpr(RHS);

  // We only want the "count * sizeof(elem)" shape, i.e., exactly one sizeof.
  if (LIsSizeof == RIsSizeof)
    return false;

  Out = BO;
  return true;
}

bool SAGenTestChecker::isFalsePositive(const Expr *SizeArg) {
  // Suppress when the entire size arg is a plain sizeof(...) of anything.
  // This covers the reported FP: memdup_user(arg, sizeof(*desc))
  return isSizeofExpr(SizeArg);
}

bool SAGenTestChecker::isMemdupUser(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "memdup_user";
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only interested in direct calls to memdup_user.
  if (!isMemdupUser(Call))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // Suppress plain sizeof(...) calls (dup of a single struct/object).
  if (isFalsePositive(SizeArg))
    return;

  // Only warn when the top-level expression (ignoring parens/casts) is exactly
  // a multiplication with exactly one side being sizeof(...).
  const BinaryOperator *TopMul = nullptr;
  if (!isTopLevelMulWithExactlyOneSizeof(SizeArg, TopMul))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, "
      "count * elem_size); multiplication may overflow.",
      N);
  // Highlight just the multiplication subexpression (the whole size arg).
  R->addRange(TopMul->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memdup_user used with count * sizeof(...) and suggests "
      "memdup_array_user",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
