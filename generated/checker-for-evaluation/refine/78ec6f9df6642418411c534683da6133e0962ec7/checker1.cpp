// /scratch/chenyuan-data/SAGEN/result-0224-bugfail-multi-o3mini/test-Concurrency-78ec6f9df6642418411c534683da6133e0962ec7/checkers/checker0.cpp
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

// Our checker only needs to analyze binding operations.
// We want to check when an assignment to the field "stats_updates" is performed
// without using atomic primitives such as READ_ONCE or WRITE_ONCE.
class SAGenTestChecker : public Checker<check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Non-atomic access on per-CPU counter", "Concurrency")) {}

  // The checkBind callback gets invoked when a value is bound to a location.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // You can add additional helper functions here if needed.
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // Ensure we have a valid statement.
  if (!StoreE)
    return;

  // Retrieve the source text from the left-hand side expression.
  // We want to check if the assignment is made to a field named "stats_updates".
  // Use the utility function ExprHasName.
  const Expr *StoreExpr = dyn_cast<Expr>(StoreE);
  if (!StoreExpr)
    return;

  // If the left-hand side does not refer to "stats_updates", we are not interested.
  if (!ExprHasName(StoreExpr, "stats_updates", C))
    return;

  // Retrieve the whole source text for the assignment operation.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(StoreE->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the source text includes the atomic primitives.
  // If it contains "READ_ONCE" or "WRITE_ONCE", assume the operation is atomic.
  if (Text.contains("READ_ONCE") || Text.contains("WRITE_ONCE"))
    return;

  // Otherwise, we have a non-atomic update operation on stats_updates.
  // Generate a bug report.

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Non-atomic update on per-CPU stats_updates may lead to a data race", N);
  Report->addRange(StoreE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects non-atomic updates on per-CPU stats_updates that can lead to data races", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
