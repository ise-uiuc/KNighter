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

#include "clang/Lex/Lexer.h" // For Lexer::getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// No extra program state is required for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> { 
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Legacy Array Copy Function", "API Migration")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportLegacyFunction(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the original call expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Check if the function being called is either memdup_user or vmemdup_user.
  bool isLegacyCall = ExprHasName(OriginExpr, "memdup_user", C) ||
                        ExprHasName(OriginExpr, "vmemdup_user", C);
  if (!isLegacyCall)
    return;
  
  // Optionally, verify that one of the arguments involves 'array_size'.
  bool foundArraySize = false;
  for (unsigned idx = 0, numArgs = Call.getNumArgs(); idx < numArgs; ++idx) {
    const Expr *ArgExpr = Call.getArgExpr(idx);
    if (!ArgExpr)
      continue;
    if (ExprHasName(ArgExpr, "array_size", C)) {
      foundArraySize = true;
      break;
    }
  }
  
  // If no indication of array_size usage is found, we do not report.
  if (!foundArraySize)
    return;
  
  reportLegacyFunction(Call, C);
}

void SAGenTestChecker::reportLegacyFunction(const CallEvent &Call, CheckerContext &C) const {
  // Generate an error node to report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Legacy array-copy function used; use memdup_array_user/vmemdup_array_user instead", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects legacy array-copy functions using memdup_user/vmemdup_user with array_size()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
