// /scratch/chenyuan-data/SAGEN/result-0224-bugfail-multi-o3mini/test-Memory-Leak-27834971f616c5e154423c578fa95e0444444ce1/checkers/checker0.cpp
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
#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker< check::BranchCondition > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Erroneous sensitive memory release")) {}

  // Callback: Invoked when a branch condition is about to be evaluated.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper function to report error
  void reportSensitiveMemoryFree(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;
  
  // Step 1: Check if the condition subtree contains a call to set_memory_decrypted().
  const CallExpr *FoundCall = findSpecificTypeInChildren<CallExpr>(Condition);
  if (!FoundCall)
    return;
  
  // Retrieve the callee identifier using DeclRefExpr.
  const Expr *CalleeExpr = FoundCall->getCallee()->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(CalleeExpr)) {
    if (!DRE->getDecl()->getIdentifier() ||
        !DRE->getDecl()->getIdentifier()->getName().equals("set_memory_decrypted"))
      return;
  } else {
    return;
  }

  // Step 2: Locate the enclosing IfStmt.
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  // Step 3: Analyze the then-branch to see if free_pages_exact() is called.
  const Stmt *ThenBranch = IfS->getThen();
  if (!ThenBranch)
    return;

  // Look for a call to free_pages_exact in the then branch:
  const CallExpr *FreeCall = findSpecificTypeInChildren<CallExpr>(ThenBranch);
  if (!FreeCall)
    return;

  const Expr *FreeCalleeExpr = FreeCall->getCallee()->IgnoreParenCasts();
  if (const auto *FreeDRE = dyn_cast<DeclRefExpr>(FreeCalleeExpr)) {
    if (FreeDRE->getDecl()->getIdentifier() &&
        FreeDRE->getDecl()->getIdentifier()->getName().equals("free_pages_exact")) {
      // Pattern matched: In the if-condition that involves set_memory_decrypted(),
      // the then branch calls free_pages_exact(). Report this as a potential bug.
      reportSensitiveMemoryFree(ThenBranch, C);
    }
  }
}

void SAGenTestChecker::reportSensitiveMemoryFree(const Stmt *S, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  // Create the bug report; message is short and clear.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Sensitive decrypted memory erroneously freed on error path.", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects erroneous freeing of sensitive decrypted memory on error paths",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
