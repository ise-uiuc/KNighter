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
#include "clang/AST/Decl.h"
#include "clang/AST/ParentMapContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state mapping: VarDecl that stores result of roundup_pow_of_two() -> argument Expr* passed to the call
REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResultMap, const VarDecl*, const Expr*)
// Program state set: arguments that were validated with an upper-bound check
REGISTER_SET_WITH_PROGRAMSTATE(ValidatedArgSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unreliable overflow check with roundup_pow_of_two", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:

      // Helpers
      bool isRoundupPow2Call(const CallEvent &Call, CheckerContext &C) const;

      const VarDecl* getAssignedVarFromCall(const CallEvent &Call, CheckerContext &C) const;

      // zero-check detector
      bool matchesZeroCheck(const Expr *Cond, const Expr *&CheckedExpr, CheckerContext &C) const;

      // pre-validation detector
      bool isPrevalidationCheck(const Expr *Cond,
                                const Expr *&ArgExprOut,
                                const Expr *&BoundExprOut,
                                CheckerContext &C) const;

      const MemRegion* exprToRegion(const Expr *E, CheckerContext &C) const;

      void reportIssue(const Stmt *Cond, CheckerContext &C) const;
};

// Determine if the call is roundup_pow_of_two(...)
bool SAGenTestChecker::isRoundupPow2Call(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Use utility for reliable name check
  return ExprHasName(Origin, "roundup_pow_of_two", C);
}

// From a call, find the VarDecl that receives the result.
// Handles: v = roundup_pow_of_two(...); and: u64 v = roundup_pow_of_two(...);
const VarDecl* SAGenTestChecker::getAssignedVarFromCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return nullptr;

  const Expr *OUnwrapped = Origin->IgnoreParenImpCasts();

  // Case 1: initialization in a decl stmt
  if (const DeclStmt *DS = findSpecificTypeInParents<DeclStmt>(Origin, C)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (const Expr *Init = VD->getInit()) {
          if (Init->IgnoreParenImpCasts() == OUnwrapped)
            return VD->getCanonicalDecl();
        }
      }
    }
  }

  // Case 2: assignment via BinaryOperator
  if (const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(Origin, C)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS();
      if (RHS && RHS->IgnoreParenImpCasts() == OUnwrapped) {
        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            return VD->getCanonicalDecl();
        }
      }
    }
  }

  return nullptr;
}

// Convert an expression to its base memory region
const MemRegion* SAGenTestChecker::exprToRegion(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

// Detect if condition is a zero-check like: !E or (E == 0)
bool SAGenTestChecker::matchesZeroCheck(const Expr *Cond, const Expr *&CheckedExpr, CheckerContext &C) const {
  if (!Cond)
    return false;
  const Expr *E = Cond->IgnoreParenCasts();

  // if (!E)
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      CheckedExpr = UO->getSubExpr()->IgnoreParenCasts();
      return true;
    }
  }

  // if (E == 0) or (0 == E)
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ) {
      llvm::APSInt Res;
      const Expr *L = BO->getLHS()->IgnoreParenCasts();
      const Expr *R = BO->getRHS()->IgnoreParenCasts();

      bool LIsZero = EvaluateExprToInt(Res, L, C) && Res.isZero();
      bool RIsZero = EvaluateExprToInt(Res, R, C) && Res.isZero();

      if (LIsZero && !RIsZero) {
        CheckedExpr = R;
        return true;
      }
      if (RIsZero && !LIsZero) {
        CheckedExpr = L;
        return true;
      }
    }
  }

  return false;
}

// Detect a pre-validation check of the form: (Arg > Bound) or (Arg >= Bound)
// where Bound is a power-of-two related expression, e.g., contains '<<' or 'BITS_PER_LONG'
bool SAGenTestChecker::isPrevalidationCheck(const Expr *Cond,
                                            const Expr *&ArgExprOut,
                                            const Expr *&BoundExprOut,
                                            CheckerContext &C) const {
  if (!Cond)
    return false;

  const Expr *E = Cond->IgnoreParenCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  bool HasShift = false;
  if (const BinaryOperator *Inner = findSpecificTypeInChildren<BinaryOperator>(RHS)) {
    if (Inner->getOpcode() == BO_Shl)
      HasShift = true;
  }
  bool MentionsBitsPerLong = ExprHasName(RHS, "BITS_PER_LONG", C);

  if (HasShift || MentionsBitsPerLong) {
    ArgExprOut = LHS;
    BoundExprOut = RHS;
    return true;
  }

  return false;
}

void SAGenTestChecker::reportIssue(const Stmt *Cond, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Do not test roundup_pow_of_two() result for 0; pre-validate input to avoid UB on 32-bit.",
      N);
  if (Cond)
    R->addRange(Cond->getSourceRange());
  C.emitReport(std::move(R));
}

// Record where roundup_pow_of_two result goes: VarDecl -> ArgExpr
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isRoundupPow2Call(Call, C))
    return;

  ProgramStateRef State = C.getState();

  const VarDecl *VD = getAssignedVarFromCall(Call, C);
  if (!VD)
    return;

  // record the argument expression
  const Expr *Origin = Call.getOriginExpr();
  const CallExpr *CE = dyn_cast_or_null<CallExpr>(Origin);
  if (!CE || CE->getNumArgs() < 1)
    return;

  const Expr *Arg = CE->getArg(0);
  if (!Arg)
    return;

  State = State->set<RoundupResultMap>(VD->getCanonicalDecl(), Arg);
  C.addTransition(State);
}

// Detect both prevalidation and the bad pattern in branch conditions.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  // Step A: mark pre-validated arguments
  {
    const Expr *ArgExpr = nullptr;
    const Expr *BoundExpr = nullptr;
    if (isPrevalidationCheck(CondE, ArgExpr, BoundExpr, C)) {
      const MemRegion *ArgReg = exprToRegion(ArgExpr, C);
      if (ArgReg) {
        State = State->add<ValidatedArgSet>(ArgReg);
      }
    }
  }

  // Step B: detect zero-check patterns
  {
    const Expr *CheckedExpr = nullptr;
    if (matchesZeroCheck(CondE, CheckedExpr, C)) {
      if (!CheckedExpr)
        goto transition;

      // Case B1: directly checking the call result
      if (const auto *CallE = dyn_cast<CallExpr>(CheckedExpr)) {
        // Make a lightweight CallEvent-like name check using ExprHasName
        if (ExprHasName(CallE, "roundup_pow_of_two", C)) {
          if (CallE->getNumArgs() >= 1) {
            const Expr *Arg = CallE->getArg(0);
            const MemRegion *ArgReg = exprToRegion(Arg, C);
            if (ArgReg) {
              if (!State->contains<ValidatedArgSet>(ArgReg)) {
                reportIssue(Condition, C);
              }
            } else {
              // If we cannot resolve the region, do not report to avoid FP
            }
          }
        }
      }
      // Case B2: checking a variable that previously received roundup_pow_of_two result
      else if (const auto *DRE = dyn_cast<DeclRefExpr>(CheckedExpr)) {
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        if (VD) {
          VD = VD->getCanonicalDecl();
          if (const Expr *Arg = State->get<RoundupResultMap>(VD)) {
            const MemRegion *ArgReg = exprToRegion(Arg, C);
            if (ArgReg) {
              if (!State->contains<ValidatedArgSet>(ArgReg)) {
                reportIssue(Condition, C);
              }
            }
          }
        }
      }
    }
  }

transition:
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unreliable overflow checks using roundup_pow_of_two result == 0 without pre-validation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
