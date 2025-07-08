#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
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

// No custom program state maps are needed for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unprotected read of work->data", "Data Race Guard")) {}

  // Callback: intercept call events.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportUnguardedAccess(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the originating call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check whether the call is to "work_data_bits".
  // Use ExprHasName for accurate matching.
  if (!ExprHasName(OriginExpr, "work_data_bits", C))
    return;

  // Now, try to find an enclosing IfStmt in the AST chain.
  // Since IfStmt is defined in "clang/AST/Stmt.h", we can use it directly.
  const IfStmt *EnclosingIf = findSpecificTypeInParents<IfStmt>(OriginExpr, C);

  // If there's an enclosing IfStmt, check if its condition mentions "from_cancel".
  bool Guarded = false;
  if (EnclosingIf && EnclosingIf->getCond()) {
    // If the condition contains "from_cancel", we assume it is guarded.
    if (ExprHasName(EnclosingIf->getCond(), "from_cancel", C))
      Guarded = true;
  }

  // If the call to work_data_bits is not guarded by an "if" checking "from_cancel",
  // report the bug.
  if (!Guarded)
    reportUnguardedAccess(Call, C);
}

void SAGenTestChecker::reportUnguardedAccess(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unprotected read of work->data could trigger spurious data race detection", ErrNode);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unprotected reading of work->data in __flush_work that can trigger spurious data race detection",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
