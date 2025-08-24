```cpp
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
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track LHS regions that currently hold the result of roundup_pow_of_two(arg).
// Map key: the base MemRegion of the variable holding the result.
// Map value: the original argument Expr* (as a tag/context; not dereferenced).
REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResultMap, const MemRegion*, const Expr*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe overflow check of roundup_pow_of_two()", "Undefined Behavior")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      bool isRoundupPow2Call(const CallExpr *CE, CheckerContext &C) const;
      void reportIssue(const Stmt *Trigger, CheckerContext &C) const;
};
} // end anonymous namespace

bool SAGenTestChecker::isRoundupPow2Call(const CallExpr *CE, CheckerContext &C) const {
  if (!CE)
    return false;
  const Expr *Origin = CE;
  return ExprHasName(Origin, "roundup_pow_of_two", C);
}

void SAGenTestChecker::reportIssue(const Stmt *Trigger, CheckerContext &C) const {
  // Optional gating: only warn when unsigned long is 32-bit or smaller.
  unsigned ULBits = C.getASTContext().getTypeSize(C.getASTContext().UnsignedLongTy);
  if (ULBits > 32)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "roundup_pow_of_two() result checked for zero; check the input before calling (avoid UB on 32-bit).",
      N);
  if (Trigger)
    R->addRange(Trigger->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  ProgramStateRef State = C.getState();

  // Try to find a CallExpr within the statement causing the bind.
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE || !isRoundupPow2Call(CE, C)) {
    // Overwritten with a non-roundup value; clear any previous mark.
    State = State->remove<RoundupResultMap>(LHSReg);
    C.addTransition(State);
    return;
  }

  // Mark the region as holding a roundup_pow_of_two result.
  const Expr *ArgE = (CE->getNumArgs() > 0) ? CE->getArg(0) : nullptr;
  State = State->set<RoundupResultMap>(LHSReg, ArgE);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  // Identify zero-check patterns.
  const Expr *RegionExpr = nullptr;     // The expression we will try to resolve to a MemRegion (do NOT strip casts before calling getMemRegionFromExpr).
  const Expr *AnalyzeExpr = nullptr;    // A normalized form for analysis (we can strip parens/casts here).

  const Expr *CondNoImp = CondE->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(CondNoImp)) {
    if (UO->getOpcode() == UO_LNot) {
      RegionExpr = UO->getSubExpr(); // keep original for region extraction
      AnalyzeExpr = UO->getSubExpr()->IgnoreParenImpCasts();
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondNoImp)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHSOrig = BO->getLHS();
      const Expr *RHSOrig = BO->getRHS();
      const Expr *LHS = LHSOrig->IgnoreParenImpCasts();
      const Expr *RHS = RHSOrig->IgnoreParenImpCasts();

      llvm::APSInt EvalRes;
      bool LHSIsZero = EvaluateExprToInt(EvalRes, LHS, C) && EvalRes.isZero();
      bool RHSIsZero = EvaluateExprToInt(EvalRes, RHS, C) && EvalRes.isZero();

      if (LHSIsZero ^ RHSIsZero) {
        // Choose the non-zero side as the expression under check.
        if (LHSIsZero) {
          RegionExpr = RHSOrig;                 // use original for region
          AnalyzeExpr = RHS;                    // use normalized for analysis
        } else {
          RegionExpr = LHSOrig;
          AnalyzeExpr = LHS;
        }
      }
    }
  } else {
    // Not a zero-check; ignore.
    return;
  }

  if (!RegionExpr || !AnalyzeExpr)
    return;

  // Case 1: Direct call in the condition.
  if (const CallExpr *InnerCE = findSpecificTypeInChildren<CallExpr>(AnalyzeExpr)) {
    if (isRoundupPow2Call(InnerCE, C)) {
      reportIssue(Condition, C);
      return;
    }
  }

  // Case 2: Variable holds a roundup_pow_of_two result.
  const MemRegion *MR = getMemRegionFromExpr(RegionExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  if (const Expr *const* Tagged = State->get<RoundupResultMap>(MR)) {
    (void)Tagged; // We don't need to use the argument, only the tag presence.
    reportIssue(Condition, C);
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe overflow checks of roundup_pow_of_two() by comparing result to zero",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
