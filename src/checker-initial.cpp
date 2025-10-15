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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// In this checker, we detect a bug pattern where an allocation (via new CSSImportantRule)
// is not checked for a null return before its pointer is used with NS_ADDREF.
// This can lead to a null pointer dereference in out-of-memory cases.

namespace {

class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked allocation", "Memory Error")) {}

  // Callback invoked before a function call is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report a bug when an unchecked allocation is found.
  void reportUncheckedAllocation(const CallEvent &Call, CheckerContext &C, const Expr *ArgExpr) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // First, get the origin expression and check if it contains "NS_ADDREF".
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "NS_ADDREF", C))
    return;

  // Ensure that NS_ADDREF is invoked with at least one argument.
  if (Call.getNumArgs() < 1)
    return;

  // Get the SVal of the first argument (the pointer subject to NS_ADDREF).
  SVal PtrVal = Call.getArgSVal(0);

  // Retrieve its corresponding expression.
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  // Get the memory region corresponding to this pointer.
  // Note: We must not call IgnoreImplicit() before getMemRegionFromExpr.
  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  // Use the program state to check whether the pointer might be null.
  const ProgramStateRef State = C.getState();
  ProgramStateRef stateNonNull, stateNull;
  if (State->assume(PtrVal, true, stateNonNull, stateNull)) {
    // If there exists a feasible state where the pointer is null,
    // report an unchecked allocation bug.
    if (stateNull)
      reportUncheckedAllocation(Call, C, ArgExpr);
  }
}

void SAGenTestChecker::reportUncheckedAllocation(const CallEvent &Call,
                                                   CheckerContext &C,
                                                   const Expr *ArgExpr) const {
  // Generate an error node in the exploded graph.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Prepare and emit a bug report.
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked allocation: new CSSImportantRule returned null before NS_ADDREF",
      N);
  report->addRange(ArgExpr->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked allocation: new CSSImportantRule returned null before NS_ADDREF",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
