#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h" // Added for ASTContext and getParents.
#include "clang/Lex/Lexer.h"
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

// Helper function to walk up the AST and find an enclosing IfStmt.
const IfStmt *findEnclosingIfStmt(const Expr *E, CheckerContext &C) {
  // Use the ASTContext directly from the CheckerContext.
  ASTContext &ACtx = C.getASTContext();
  const Stmt *Current = E;
  while (true) {
    // Get the direct parents of the current expression/statement.
    auto Parents = ACtx.getParents(*Current);
    if (Parents.empty())
      break;
    // Pick the first parent that is a Stmt.
    const Stmt *ParentStmt = Parents[0].get<Stmt>();
    if (!ParentStmt)
      break;
    if (const IfStmt *IfS = dyn_cast<IfStmt>(ParentStmt))
      return IfS;
    Current = ParentStmt;
  }
  return nullptr;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unvalidated Buffer Length",
         "User supplied buffer length not validated before copy operation")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportUnvalidatedBufferLength(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the original call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use utility to check that we're looking at a call to copy_from_sockptr.
  if (!ExprHasName(OriginExpr, "copy_from_sockptr", C))
    return;

  // Ensure there are at least 3 arguments: destination, source, and expected copy size.
  if (Call.getNumArgs() < 3)
    return;

  // Evaluate the third argument (expected copy size) to an integer.
  const Expr *ExpectedSizeArg = Call.getArgExpr(2);
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, ExpectedSizeArg, C))
    return;

  // Retrieve the expected size value.
  const int64_t ExpectedSize = EvalRes.getExtValue();
  (void)ExpectedSize; // Currently unused, but may be used in future enhancements.

  // Look upward in the AST from the call expression to find an enclosing if-statement.
  const IfStmt *EnclosingIf = findEnclosingIfStmt(OriginExpr, C);
  bool Validated = false;
  if (EnclosingIf) {
    // Get the condition of the if-statement.
    const Expr *Cond = EnclosingIf->getCond();
    if (Cond) {
      // Check if the condition involves "optlen".
      // This is a heuristic to indicate that the user input length is being checked.
      if (ExprHasName(Cond, "optlen", C))
        Validated = true;
    }
  }

  // If there is no enclosing validation of "optlen", report a bug.
  if (!Validated)
    reportUnvalidatedBufferLength(Call, C);
}

void SAGenTestChecker::reportUnvalidatedBufferLength(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "User buffer length not validated before calling copy_from_sockptr", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects missing validation for user parameter 'optlen' before copying from user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
