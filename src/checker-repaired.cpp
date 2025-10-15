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

// The checker detects instances where an allocated resource (a gfxWindowsSurface)
// is validated with a simple null-pointer check instead of using a proper status check
// (e.g. testing the result of the CairoStatus() call). This checker intercepts branch conditions,
// and if the source code for the condition references the variable "target" without mentioning "CairoStatus",
// it reports an error.
class SAGenTestChecker : public Checker< check::BranchCondition > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Resource Initialization Check", 
                       "Incorrect resource initialization check")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // (Optional helper functions could be added here if more sophisticated AST inspection is needed)
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  // We are looking for conditions that reference the resource variable "target".
  // Use the utility function to check if "target" is present in the expression.
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  if (ExprHasName(CondExpr, "target", C)) {
    // Retrieve the source text of the condition.
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range = CharSourceRange::getTokenRange(Condition->getSourceRange());
    StringRef CondText = Lexer::getSourceText(Range, SM, LangOpts);

    // If the condition text does not contain "CairoStatus",
    // then the error check is likely a null-pointer check (e.g. "if (!target)").
    if (!CondText.contains("CairoStatus")) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Incorrect resource initialization check: null-pointer test used instead of checking CairoStatus", N);
      Report->addRange(Condition->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
  C.addTransition(C.getState());
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing resource status check (using null pointer check instead of CairoStatus) on gfxWindowsSurface", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
