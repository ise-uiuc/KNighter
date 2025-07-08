#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
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

// This checker intercepts calls to roundup_pow_of_two()
// and reports an error if no safeguard condition against
// overflow (e.g., a check against "1UL << 31") exists in a surrounding if-statement.
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked roundup_pow_of_two",
         "Potential Overflow on 32-bit architectures")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression for the call.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Check if the call is to "roundup_pow_of_two" using the origin's source text.
  if (!ExprHasName(Origin, "roundup_pow_of_two", C))
    return;

  // Look upward in the AST for a surrounding IfStmt that might be guarding the call.
  const IfStmt *IfParent = findSpecificTypeInParents<IfStmt>(Origin, C);
  bool hasOverflowCheck = false;
  
  if (IfParent) {
    const Expr *Cond = IfParent->getCond();
    if (Cond) {
      // Check if the condition text contains the check for "1UL << 31"
      // which is used in the fix to preclude overflow.
      if (ExprHasName(Cond, "1UL << 31", C))
        hasOverflowCheck = true;
    }
  }
  
  // If no proper check guarding the call is found, emit a bug report.
  if (!hasOverflowCheck) {
    ProgramStateRef State = C.getState();
    ExplodedNode *N = C.generateNonFatalErrorNode(State);
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
                      *BT,
                      "Unchecked use of roundup_pow_of_two: potential overflow on 32-bit arches",
                      N);
    Report->addRange(Origin->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked use of roundup_pow_of_two that can overflow on 32-bit architectures",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
