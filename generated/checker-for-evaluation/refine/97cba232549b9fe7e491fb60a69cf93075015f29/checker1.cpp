// /scratch/chenyuan-data/SAGEN/result-0224-bugfail-multi-o3mini/test-Buffer-Overflow-97cba232549b9fe7e491fb60a69cf93075015f29/checkers/checker6.cpp
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
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// This checker detects potential buffer overflows where an array access uses
// an offset (i+1) without ensuring that the loop iteration stops early enough.
class SAGenTestChecker : public Checker<check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer Overflow",
                                        "Out-of-bound Array Access")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  void reportBug(const Stmt *S, CheckerContext &C) const;
};

/// reportBug - Helper function to report a potential bug.
void SAGenTestChecker::reportBug(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential buffer overflow: array index offset may exceed the allocated bounds", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

/// checkBind - This callback is executed when a binding occurs.
/// We look for an ArraySubscriptExpr whose index expression is a binary addition  
/// with a constant literal 1, and whose base expression's source text contains "dc->links".
/// Then we try to locate the surrounding ForStmt. If the loop condition text does not subtract 1,
/// then we report a potential bug.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Look for an ArraySubscriptExpr in the statement.
  const ArraySubscriptExpr *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S);
  if (!ASE)
    return;

  // Check that the base expression contains "dc->links".
  const Expr *BaseExpr = ASE->getBase()->IgnoreParenCasts();
  if (!BaseExpr || !ExprHasName(BaseExpr, "dc->links", C))
    return;

  // Check the index expression.
  const Expr *IndexExpr = ASE->getIdx()->IgnoreParenCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(IndexExpr);
  if (!BO)
    return;

  // We are looking for an addition expression.
  if (BO->getOpcode() != BO_Add)
    return;

  bool HasOneLiteral = false;
  // Check if either operand is an integer literal with value 1.
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(BO->getLHS()->IgnoreParenCasts()))
    if (IL->getValue() == 1)
      HasOneLiteral = true;
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(BO->getRHS()->IgnoreParenCasts()))
    if (IL->getValue() == 1)
      HasOneLiteral = true;
  if (!HasOneLiteral)
    return;

  // Retrieve the enclosing ForStmt to analyze the loop condition.
  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(S, C);
  if (!FS)
    return;

  // Get the loop condition expression.
  const Expr *CondExpr = FS->getCond();
  if (!CondExpr)
    return;

  // Extract the source text of the loop's condition.
  const SourceManager &SM = C.getSourceManager();
  LangOptions LangOpts = C.getLangOpts();
  CharSourceRange CSRange = CharSourceRange::getTokenRange(CondExpr->getSourceRange());
  StringRef CondText = Lexer::getSourceText(CSRange, SM, LangOpts);

  // Check if the loop condition subtracts one. If it does, it likely avoids the overflow.
  // We do a simple substring check for "-". If "- 1" appears, assume it is safe.
  if (CondText.contains("-") && CondText.contains("1"))
    return;

  // Otherwise, report the potential bug.
  reportBug(S, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential buffer overflow due to index offset with array access", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
