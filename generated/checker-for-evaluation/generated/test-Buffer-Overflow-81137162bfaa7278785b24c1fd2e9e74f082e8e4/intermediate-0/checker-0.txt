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
#include "clang/AST/Expr.h" // For handling Expr types

using namespace clang;
using namespace ento;
using namespace taint;

// For this checker we do not need to customize program states.

namespace {

class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unbounded strcpy into fixed-size buffer")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Use ExprHasName to check that the call originates from a "strcpy" call.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin || !ExprHasName(Origin, "strcpy", C))
    return;
  
  // Retrieve the destination expression (first argument) and try to get its fixed size.
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;

  llvm::APInt ArraySize(32, 0);
  bool HasFixedSize = getArraySizeFromExpr(ArraySize, DestExpr);
  if (!HasFixedSize)
    return; // Destination is not a fixed-size array; nothing to check here.

  bool ReportBug = false;
  
  // Optionally, check the source argument (second argument).
  const Expr *SrcExpr = Call.getArgExpr(1);
  if (SrcExpr) {
    llvm::APInt StringSize(32, 0);
    // If the source is a string literal, obtain its size.
    if (getStringSize(StringSize, SrcExpr)) {
      // If the string literal's length is greater than or equal to
      // the destination buffer size, then it's a potential vulnerability.
      if (StringSize.uge(ArraySize))
        ReportBug = true;
    } else {
      // Cannot determine the literal size; assume potential vulnerability.
      ReportBug = true;
    }
  } else {
    // No source argument; nothing to check.
    return;
  }
  
  if (ReportBug) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Unbounded strcpy into fixed-size buffer can overflow the destination buffer",
        N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unbounded strcpy into fixed-size buffer", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
