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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper function to check if a given if-statement condition contains a safe-range check.
// Specifically, we look if the condition text contains "1UL << 31" and "max_entries".
static bool hasSafeRangeCheck(const Stmt *S, CheckerContext &C) {
  // Try to find an enclosing if-statement.
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(S, C);
  if (!IfS)
    return false;
    
  const Expr *Cond = IfS->getCond();
  if (!Cond)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange CondRange = CharSourceRange::getTokenRange(Cond->getSourceRange());
  StringRef CondText = Lexer::getSourceText(CondRange, SM, LangOpts);

  // Check if the condition text appears to enforce a safe range on max_entries.
  // We check for a comparison with "1UL << 31" (or equivalent) and "max_entries".
  if (CondText.contains("1UL << 31") && CondText.contains("max_entries"))
    return true;

  return false;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked input to roundup_pow_of_two")) {}

  // Check pre-call events.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // (No additional self-defined functions required beyond our helper above.)
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // First, ensure that the call expression has an origin expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // We want to intercept only calls to "roundup_pow_of_two".
  // Use the utility function ExprHasName on the origin expression.
  if (!ExprHasName(OriginExpr, "roundup_pow_of_two", C))
    return;

  // Retrieve the first argument of the function.
  if (Call.getNumArgs() < 1)
    return;
    
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;
    
  // Check if the argument expression's source text contains "max_entries"
  // to ensure we are looking at the intended use.
  if (!ExprHasName(ArgExpr, "max_entries", C))
    return;

  // Look upward in the AST from the origin of the call to see if there is an if-statement 
  // that contains a safe-range check (e.g. comparing max_entries against "1UL << 31").
  if (hasSafeRangeCheck(OriginExpr, C))
    return; // A safe check is present

  // Otherwise, the call to roundup_pow_of_two is not preceded by a safe-range check.
  // Generate a bug report.
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unchecked input to roundup_pow_of_two: possible overflow on 32-bit arches", N);
    Report->addRange(OriginExpr->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects calls to roundup_pow_of_two with unchecked max_entries potentially causing overflow on 32-bit arches",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
