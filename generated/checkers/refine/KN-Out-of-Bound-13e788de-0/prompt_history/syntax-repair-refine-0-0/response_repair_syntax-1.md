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
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Off-by-one bound check", "Logic")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  static StringRef getExprText(const Expr *E, CheckerContext &C) {
    if (!E)
      return StringRef();
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
    return Lexer::getSourceText(Range, SM, LangOpts);
  }

  static bool nameLooksLikeCountBound(StringRef Name) {
    // Heuristic: Names that denote counts/sizes/maximums
    // We intentionally do NOT match "INDEX" to avoid confusing last-index checks.
    std::string Lower = Name.lower();
    return Lower.find("max") != std::string::npos ||
           Lower.find("count") != std::string::npos ||
           Lower.find("num") != std::string::npos ||
           Lower.find("size") != std::string::npos;
  }

  static bool isDeclRefWithNameLikeCount(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *II = DRE->getDecl()->getIdentifier())
        return nameLooksLikeCountBound(II->getName());
      // Enum constants or unnamed identifiers may not have IdentifierInfo,
      // but they still have a Decl name string.
      if (const NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(ME->getMemberDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    return false;
  }

  static bool isCompositeBoundExpr(const Expr *E) {
    // True if E is a non-trivial expression (e.g., MAX - 1, MAX + 1, sizeof...)
    // We only want to consider a plain DeclRefExpr/MemberExpr bound to reduce FPs.
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    return !isa<DeclRefExpr>(E) && !isa<MemberExpr>(E);
  }

  static bool isLikelyErrorReturn(const ReturnStmt *RS, CheckerContext &C) {
    if (!RS)
      return false;
    const Expr *RV = RS->getRetValue();
    if (!RV)
      return false;

    // Try to evaluate to integer and see if it's negative.
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, RV, C))
      return Val.isSigned() ? Val.isNegative() : false;

    // If not foldable, still consider it likely if source contains a known errno or negative.
    StringRef Txt = getExprText(RV, C);
    if (Txt.contains("-E") || Txt.contains("ERR_PTR") || Txt.contains("error") ||
        Txt.contains("-EINVAL") || Txt.contains("-EFAULT") || Txt.contains("-ENODATA") ||
        Txt.contains("-ENOLINK") || Txt.contains("-ENOLCK") || Txt.contains("-ERANGE"))
      return true;

    return false;
  }

  static bool thenBranchHasEarlyErrorReturn(const IfStmt *IS, CheckerContext &C) {
    if (!IS)
      return false;
    const Stmt *ThenS = IS->getThen();
    if (!ThenS)
      return false;

    // Look for a ReturnStmt somewhere in the Then branch and check if it's an error return.
    const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
    if (!RS)
      return false;

    return isLikelyErrorReturn(RS, C);
  }

  // A more precise bound check predicate: 'Var > Bound' where Bound is a simple
  // MAX/COUNT/NUM/SIZE-like identifier and not a composite expression or integer literal.
  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    if (isa<IntegerLiteral>(Bound))
      return false; // do not treat integer literal RHS as a MAX-like bound

    if (isCompositeBoundExpr(Bound))
      return false; // do not accept 'MAX - 1' or other complex forms

    return isDeclRefWithNameLikeCount(Bound);
  }

  // Additional guard to reject obvious false positives.
  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    // Reject when RHS is a small integer literal like 0, 1, 2. These are often last-index checks.
    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
      // Anything small (<= 2) is very likely a last-index style check: 'idx > 1' for 0..1.
      if (IL->getValue().ule(2))
        return true;
    }

    // If RHS text contains an explicit '- 1' pattern, it's likely correct: 'idx > MAX - 1'
    StringRef Txt = getExprText(RHS, C);
    if (Txt.contains("- 1") || Txt.contains("-1"))
      return true;

    return false;
  }
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  // Only consider If conditions.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  // We only consider simple relational comparisons with '>'.
  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  if (!LHS || !RHS)
    return;

  // Bound should be a simple MAX/COUNT/NUM/SIZE-like identifier.
  if (!isPlainMaxLikeBound(RHS, C))
    return;

  // The Then branch should look like an error path with early return.
  if (!thenBranchHasEarlyErrorReturn(IS, C))
    return;

  // Skip degenerate cases like "5 > MAX".
  if (isa<IntegerLiteral>(LHS))
    return;

  // Additional false-positive guards.
  if (isFalsePositive(LHS, RHS, C))
    return;

  // Report the likely off-by-one check.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation",
      N);
  R->addRange(Condition->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one index validation using '>' instead of '>=' against MAX-like bounds",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
