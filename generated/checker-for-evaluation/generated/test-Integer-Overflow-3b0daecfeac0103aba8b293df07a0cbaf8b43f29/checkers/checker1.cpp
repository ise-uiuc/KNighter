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

// No additional program state maps are needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Integer Overflow in Allocation", "Security")) {}

  // Callback function: checkPreCall
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  
private:
  // Self-defined helper function to report a potential bug.
  void reportPotentialOverflow(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression of the call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
    
  // Use the utility function to check the function name.
  if (!ExprHasName(OriginExpr, "kzalloc", C))
    return;
  
  // kzalloc is typically called with two arguments.
  if (Call.getNumArgs() < 1)
    return;

  // Retrieve the size argument (typically the first argument).
  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;
  
  // Look downward in the AST of the size argument for a multiplication operator.
  const BinaryOperator *BinOp = findSpecificTypeInChildren<BinaryOperator>(SizeArg);
  // Check if the found BinaryOperator is a multiplication operation.
  if (BinOp && BinOp->getOpcode() == BO_Mul) {
    reportPotentialOverflow(Call, C);
  }
}

void SAGenTestChecker::reportPotentialOverflow(const CallEvent &Call, CheckerContext &C) const {
  // Generate a non-fatal error node to report the potential bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential integer overflow in kzalloc() call; consider using kcalloc() instead", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential integer overflow in kzalloc() calls (consider using kcalloc() instead)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
