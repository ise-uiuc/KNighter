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
  bool looksLikeMaxBound(const Expr *E, CheckerContext &C) const;
  bool isEarlyReturnInThen(const IfStmt *IS) const;
};

bool SAGenTestChecker::looksLikeMaxBound(const Expr *E,
                                         CheckerContext &C) const {
  if (!E)
    return false;

  // If the expression source contains "MAX", we consider it a bound-like expr.
  if (ExprHasName(E, "MAX", C))
    return true;

  // If it's a DeclRefExpr whose name contains "MAX", accept it.
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts())) {
    if (const auto *II = DRE->getDecl()->getIdentifier()) {
      if (II->getName().contains("MAX"))
        return true;
    }
  }

  // Alternatively, if it folds to an integer constant, also accept.
  llvm::APSInt Dummy;
  if (EvaluateExprToInt(Dummy, E, C))
    return true;

  return false;
}

bool SAGenTestChecker::isEarlyReturnInThen(const IfStmt *IS) const {
  if (!IS)
    return false;
  const Stmt *ThenS = IS->getThen();
  if (!ThenS)
    return false;

  // Look for a ReturnStmt somewhere in the Then branch.
  const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
  return RS != nullptr;
}

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

  // We only consider simple relational comparisons.
  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_LT)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  // Normalize to "Var > Bound".
  const Expr *VarExpr = nullptr;
  const Expr *BoundExpr = nullptr;
  if (Op == BO_GT) {
    VarExpr = LHS;
    BoundExpr = RHS;
  } else if (Op == BO_LT) {
    // "A < B" is equivalent to "B > A".
    VarExpr = RHS;
    BoundExpr = LHS;
  }

  if (!VarExpr || !BoundExpr)
    return;

  // Bound should look like a MAX-like constant or fold to an int.
  if (!looksLikeMaxBound(BoundExpr, C))
    return;

  // The Then branch should look like an error path with early return.
  if (!isEarlyReturnInThen(IS))
    return;

  // Skip degenerate cases like "5 > MAX".
  if (isa<IntegerLiteral>(VarExpr))
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
