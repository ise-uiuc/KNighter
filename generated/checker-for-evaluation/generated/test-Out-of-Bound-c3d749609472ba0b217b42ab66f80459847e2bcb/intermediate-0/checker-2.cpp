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
// Additional includes needed
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

/// A helper template that recursively searches for a specific type
/// in the children of a statement.
template <typename T>
static const T *findSpecificTypeInChildren(const Stmt *S) {
  if (!S)
    return nullptr;
  if (const T *Result = dyn_cast<T>(S))
    return Result;
  for (const Stmt *Child : S->children()) {
    if (const T *Result = findSpecificTypeInChildren<T>(Child))
      return Result;
  }
  return nullptr;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Incorrect loop boundary usage")) {}

  // Callback: invoked to check the condition in branch statements (loops included)
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;
    
  // We expect the condition to be an expression.
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  // Check if the condition text contains "dc->caps.max_links".
  // This signal indicates that the loop condition is using the external capability field.
  if (ExprHasName(CondExpr, "dc->caps.max_links", C)) {
    // Optionally, look into the children of the condition to check if "secure_display_ctxs" is used.
    // This extra bit of context can help ensure that this boundary is critical.
    const Stmt *Child = findSpecificTypeInChildren<DeclRefExpr>(Condition);
    bool usesSecureDisplay = false;
    if (Child) {
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Child))
        if (DRE->getDecl()->getNameAsString() == "secure_display_ctxs")
          usesSecureDisplay = true;
    }

    // Regardless of the extra check, report the bug.
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
      
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, 
        "Buffer iteration using incorrect boundary (max_links) may lead to overflow", 
        ErrNode);
    Report->addRange(Condition->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of dc->caps.max_links in loop boundary instead of mode_info.num_crtc, which may lead to buffer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
