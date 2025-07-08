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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked use of roundup_pow_of_two",
                                         "Integer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  /// reportBug - Emit a bug report indicating that the argument to
  /// roundup_pow_of_two is not guarded against an unsafe value.
  void reportBug(const CallEvent &Call, const Expr *OriginExpr, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the origin expression to verify the callee name via ExprHasName.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check that this call is to roundup_pow_of_two.
  if (!ExprHasName(OriginExpr, "roundup_pow_of_two", C))
    return;

  // There should be exactly one argument.
  if (Call.getNumArgs() < 1)
    return;
    
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  llvm::APSInt EvalRes;
  constexpr uint64_t Threshold = 1ULL << 31;

  // If the argument can be evaluated as a constant integer.
  if (EvaluateExprToInt(EvalRes, ArgExpr, C)) {
    uint64_t ArgVal = EvalRes.getZExtValue();
    // If the constant is above the safe threshold, it's an error.
    if (ArgVal > Threshold) {
      reportBug(Call, OriginExpr, C);
      return;
    }
    // Otherwise, the usage is safe.
    return;
  }

  // For non-constant arguments, check for guard conditions upstairs
  const IfStmt *GuardIf = findSpecificTypeInParents<IfStmt>(OriginExpr, C);
  if (GuardIf) {
    const Expr *CondExpr = GuardIf->getCond();
    if (CondExpr) {
      // Check if the condition source text contains both "max_entries" and "1UL<<31"
      if (ExprHasName(CondExpr, "max_entries", C) &&
          ExprHasName(CondExpr, "1UL<<31", C))
        return; // Guard condition found, so assume the check is in place.
    }
  }
  
  // If no guard is found, then report the bug.
  reportBug(Call, OriginExpr, C);
}

void SAGenTestChecker::reportBug(const CallEvent &Call, const Expr *OriginExpr,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Unchecked use of roundup_pow_of_two: argument not validated against safe range "
            "for 32-bit arches, potential undefined behavior due to overflow", N);
  Report->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked use of roundup_pow_of_two that can lead to undefined behavior on 32-bit arches", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
