#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"

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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// The checker will trigger on array subscripts.
class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Potential Out-of-Bounds Array Access")) {}

  // Callback for each ArraySubscriptExpr.
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

private:
  // Helper to determine if the current function is the target function.
  bool inTargetFunction(const CheckerContext &C) const;

  // Helper to check if the given IfStmt condition contains a bounds-check.
  bool hasBoundsCheck(const Stmt *S, CheckerContext &C) const;
};

bool SAGenTestChecker::inTargetFunction(const CheckerContext &C) const {
  // Traverse up to the enclosing function.
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;

  const Decl *D = LCtx->getDecl();
  if (!D)
    return false;

  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return false;

  // Check if the function name is "cm_helper_translate_curve_to_hw_format"
  return FD->getName() == "cm_helper_translate_curve_to_hw_format";
}

bool SAGenTestChecker::hasBoundsCheck(const Stmt *S, CheckerContext &C) const {
  // Traverse upward in the AST to look for an if-statement
  // that has a condition including "TRANSFER_FUNC_POINTS".
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(S, C);
  while (IfS) {
    const Expr *Cond = IfS->getCond();
    if (Cond) {
      // Retrieve source text for condition.
      const SourceManager &SM = C.getSourceManager();
      const LangOptions &LangOpts = C.getLangOpts();
      CharSourceRange Range = CharSourceRange::getTokenRange(Cond->getSourceRange());
      StringRef CondText = Lexer::getSourceText(Range, SM, LangOpts);
      // Check if the text contains the constant used for bounds.
      if (CondText.contains("TRANSFER_FUNC_POINTS"))
        return true;
    }
    // Try to find an outer if-statement.
    IfS = findSpecificTypeInParents<IfStmt>(IfS, C);
  }
  return false;
}

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                      CheckerContext &C) const {
  // Only consider cases inside the target function.
  if (!inTargetFunction(C))
    return;

  // Get the base expression of the array access.
  const Expr *BaseExpr = ASE->getBase()->IgnoreParenCasts();
  if (!BaseExpr)
    return;

  // Use our utility function ExprHasName on the base expression.
  // Check if the base expression is accessing one of the transfer function points: 
  // "tf_pts.red", "tf_pts.green", or "tf_pts.blue".
  if (!(ExprHasName(BaseExpr, "tf_pts.red", C) ||
        ExprHasName(BaseExpr, "tf_pts.green", C) ||
        ExprHasName(BaseExpr, "tf_pts.blue", C)))
    return;

  // Now check the index expression. We expect the index to use the variable "i".
  const Expr *IndexExpr = ASE->getIdx()->IgnoreParenCasts();
  if (!IndexExpr)
    return;

  // Check if the index expression contains "i". We do this by examining the source text.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange IndexRange = CharSourceRange::getTokenRange(IndexExpr->getSourceRange());
  StringRef IndexText = Lexer::getSourceText(IndexRange, SM, LangOpts);
  if (!IndexText.contains("i"))
    return;

  // Look upward in the AST from the ArraySubscriptExpr to see if there is a branch condition (if-statement)
  // that checks for bounds against TRANSFER_FUNC_POINTS.
  if (hasBoundsCheck(ASE, C))
    return; // A bounds check exists, so nothing to warn.

  // No bounds check found. Report the potential bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Array access using index 'i' without ensuring it is within TRANSFER_FUNC_POINTS", N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects access to transfer function points without proper index bounds check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
