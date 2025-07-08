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
#include "clang/AST/ASTContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

/* 
   This checker detects unsafe string copying into a fixed-size buffer.
   It intercepts calls to strcpy() and reports a warning if the destination
   buffer is a fixed-size array. If the source string is known (e.g., a string literal)
   and its length exceeds the destination buffer size, the checker reports a bug.
   Even if the source cannot be determined, the fixed-size nature of the buffer can 
   still signal a potential risk.
*/
class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unsafe string copy", "Security")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the origin expression of the call (the actual call expression).
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use ExprHasName to accurately check if the function being called is strcpy.
  if (!ExprHasName(OriginExpr, "strcpy", C))
    return;

  // Ensure that strcpy has at least two arguments.
  if (Call.getNumArgs() < 2)
    return;

  // Retrieve the destination argument (first argument).
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  // Attempt to get the fixed-size of the destination array.
  llvm::APInt ArraySize(32, 0);
  if (!getArraySizeFromExpr(ArraySize, DestExpr))
    return; // Not a fixed-size array, so we do not report a bug.

  // Retrieve the source argument (second argument).
  const Expr *SrcExpr = Call.getArgExpr(1);
  llvm::APInt StringSize(32, 0);
  // Try to determine the length of the source string if it is a literal.
  bool SourceIsString = getStringSize(StringSize, SrcExpr);

  // Decide when to report the bug.
  // Report if the source is a literal and its length exceeds the size of the destination,
  // or if the source is not a literal (i.e., its length cannot be determined).
  bool ReportBug = false;
  if (SourceIsString && StringSize.getZExtValue() > ArraySize.getZExtValue())
    ReportBug = true;
  else if (!SourceIsString)
    ReportBug = true;

  if (!ReportBug)
    return;

  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unsafe string copy into fixed-size buffer detected. Use bounds-checked copy functions (e.g., strscpy).",
      N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe string copying into fixed-size buffers using strcpy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
