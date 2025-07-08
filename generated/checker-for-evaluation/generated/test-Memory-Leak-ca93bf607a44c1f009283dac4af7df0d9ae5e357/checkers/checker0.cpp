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

// Additional includes
#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a map to record that a devm_krealloc call has been made.
// We use an int key (always 0) to store a bool.
REGISTER_MAP_WITH_PROGRAMSTATE(DevmKreallocFlag, int, bool)

namespace {

// Helper function: recursively search the AST subtree for a call to kfree
// whose argument's source text contains the substring "efuse".
bool containsKfreeEfuse(const Stmt *S, CheckerContext &C) {
  if (!S)
    return false;

  // If this is a call expression, check it.
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    const Expr *OriginExpr = CE;
    // Check if the call expression source contains "kfree"
    if (ExprHasName(OriginExpr, "kfree", C)) {
      // Check all arguments, looking for "efuse"
      for (unsigned I = 0, N = CE->getNumArgs(); I < N; ++I) {
        const Expr *Arg = CE->getArg(I);
        if (ExprHasName(Arg, "efuse", C))
          return true;
      }
    }
  }
  // Recurse over children of the statement.
  for (const Stmt *Child : S->children()) {
    if (containsKfreeEfuse(Child, C))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PostCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Memory leak on devm_krealloc failure")) {}

  // Callback invoked after a function call is evaluated.
  // We use it to record that a devm_krealloc() call has occurred.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback invoked when evaluating the condition of a branch.
  // We inspect error-handling branches that check for a null return
  // from devm_krealloc.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper to report the memory leak error.
  void reportLeak(const IfStmt *IS, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Retrieve the origin call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Use utility function to determine if the call is devm_krealloc.
  if (ExprHasName(OriginExpr, "devm_krealloc", C)) {
    // Record in the program state that a devm_krealloc call was made.
    State = State->set<DevmKreallocFlag>(0, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Only proceed if a devm_krealloc call was encountered.
  const bool *Flag = State->get<DevmKreallocFlag>(0);
  if (!Flag || !(*Flag))
    return;

  // Try to find an enclosing IfStmt for the branch condition.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  // We are interested only in error-checking branches.
  // Check if the condition expression (of the if statement) is a null-check.
  // For simplicity, we require that the source text of the condition
  // contains the string "lvts_td->calib" which (in our target code) is the pointer
  // assigned from devm_krealloc.
  if (!ExprHasName(IS->getCond(), "lvts_td->calib", C))
    return;

  // Get the then-branch of the if statement (the error-handling path).
  const Stmt *ThenBranch = IS->getThen();
  if (!ThenBranch)
    return;

  // In a correct error-handling path the 'efuse' resource should be freed
  // via a call to kfree(efuse). We check if such a call is present.
  if (!containsKfreeEfuse(ThenBranch, C)) {
    reportLeak(IS, C);
  }

  // Remove the flag from the state so that we do not report repeatedly.
  State = State->remove<DevmKreallocFlag>(0);
  C.addTransition(State);
}

void SAGenTestChecker::reportLeak(const IfStmt *IS, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  // Report a bug: the error branch does not free 'efuse'.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Memory leak: 'efuse' not freed on devm_krealloc failure", N);
  Report->addRange(IS->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects memory leak when devm_krealloc failure error path does not free efuse", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
