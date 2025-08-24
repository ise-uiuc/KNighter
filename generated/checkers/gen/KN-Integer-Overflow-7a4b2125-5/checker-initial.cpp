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

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables that currently hold the result of roundup_pow_of_two(...)
REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker()
        : BT(new BugType(this,
                         "Unreliable overflow check with roundup_pow_of_two",
                         "API Misuse")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      static bool isRoundupPowOfTwoExpr(const Expr *E, CheckerContext &C);
      static bool isZeroIntExpr(const Expr *E, CheckerContext &C);
      static bool is32BitUnsignedLong(ASTContext &ACtx);
      static const MemRegion *getVarRegion(const Expr *E, CheckerContext &C);

      void markRegionAsRoundup(ProgramStateRef &State, const MemRegion *MR) const;
      void unmarkRegion(ProgramStateRef &State, const MemRegion *MR) const;
      void reportUnreliableZeroCheck(const Stmt *Condition, CheckerContext &C) const;
};

// ---- Helper implementations ----

bool SAGenTestChecker::isRoundupPowOfTwoExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  // Check by source name occurrence for robustness (works with macros/inlines).
  return ExprHasName(E, "roundup_pow_of_two", C);
}

bool SAGenTestChecker::isZeroIntExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    return Res == 0;
  }
  return false;
}

bool SAGenTestChecker::is32BitUnsignedLong(ASTContext &ACtx) {
  return ACtx.getTypeSize(ACtx.UnsignedLongTy) == 32;
}

const MemRegion *SAGenTestChecker::getVarRegion(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  // Do not IgnoreImplicit() before getMemRegionFromExpr per guidance.
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

void SAGenTestChecker::markRegionAsRoundup(ProgramStateRef &State, const MemRegion *MR) const {
  if (!MR) return;
  State = State->set<RoundupResMap>(MR, true);
}

void SAGenTestChecker::unmarkRegion(ProgramStateRef &State, const MemRegion *MR) const {
  if (!MR) return;
  State = State->remove<RoundupResMap>(MR);
}

void SAGenTestChecker::reportUnreliableZeroCheck(const Stmt *Condition, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unreliable overflow check: testing result of roundup_pow_of_two() against 0 on 32-bit",
      N);
  R->addRange(Condition->getSourceRange());
  C.emitReport(std::move(R));
}

// ---- Checker callbacks ----

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD) continue;

    const Expr *Init = VD->getInit();
    // Get the region of the declared variable
    SValBuilder &SVB = C.getSValBuilder();
    SVal LVal = SVB.getLValue(VD, C.getLocationContext());
    const MemRegion *MR = LVal.getAsRegion();
    if (MR) MR = MR->getBaseRegion();

    if (!MR)
      continue;

    if (!Init) {
      // No initializer: variable does not hold roundup result at this point.
      unmarkRegion(State, MR);
      continue;
    }

    bool Mark = false;
    // Direct use of roundup_pow_of_two in initializer
    if (isRoundupPowOfTwoExpr(Init, C)) {
      Mark = true;
    } else {
      // Propagate from another variable that already marked
      if (const MemRegion *RHSReg = getVarRegion(Init, C)) {
        if (State->get<RoundupResMap>(RHSReg))
          Mark = true;
      }
    }

    if (Mark)
      markRegionAsRoundup(State, MR);
    else
      unmarkRegion(State, MR);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (LHSReg) LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    // Nothing to do without a region
    return;
  }

  // We only care about explicit assignments here.
  const BinaryOperator *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO) {
    BO = findSpecificTypeInParents<BinaryOperator>(S, C);
  }
  if (!BO || !BO->isAssignmentOp() || BO->getOpcode() != BO_Assign) {
    // Not a simple assignment; conservatively unmark if value is not a direct propagate
    // but to avoid noise, just return.
    return;
  }

  const Expr *RHS = BO->getRHS();
  bool Mark = false;

  if (isRoundupPowOfTwoExpr(RHS, C)) {
    Mark = true;
  } else {
    // Propagate marker if RHS is a variable already marked
    if (const MemRegion *RHSReg = getVarRegion(RHS, C)) {
      if (State->get<RoundupResMap>(RHSReg))
        Mark = true;
    }
  }

  if (Mark)
    markRegionAsRoundup(State, LHSReg);
  else
    unmarkRegion(State, LHSReg);

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;

  // Only warn on targets where unsigned long is 32-bit,
  // which is where roundup_pow_of_two can hit UB via 1UL << 32.
  if (!is32BitUnsignedLong(C.getASTContext()))
    return;

  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // A) if (!X)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE->IgnoreParens())) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *InnerRaw = UO->getSubExpr(); // do not strip casts before region query
      // Case A1: variable or lvalue expr that refers to a region we track
      if (const MemRegion *MR = getVarRegion(InnerRaw, C)) {
        if (MR->getBaseRegion() && State->get<RoundupResMap>(MR->getBaseRegion())) {
          reportUnreliableZeroCheck(Condition, C);
          return;
        }
      }
      // Case A2: direct call to roundup_pow_of_two(...)
      if (const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(InnerRaw)) {
        if (ExprHasName(CE, "roundup_pow_of_two", C)) {
          reportUnreliableZeroCheck(Condition, C);
          return;
        }
      }
    }
  }

  // B) if (X == 0) or if (0 == X)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE->IgnoreParens())) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS();
      const Expr *R = BO->getRHS();

      if (isZeroIntExpr(L, C)) {
        // Check RHS either variable marked or direct call
        if (const MemRegion *MR = getVarRegion(R, C)) {
          if (MR->getBaseRegion() && State->get<RoundupResMap>(MR->getBaseRegion())) {
            reportUnreliableZeroCheck(Condition, C);
            return;
          }
        }
        if (const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(R)) {
          if (ExprHasName(CE, "roundup_pow_of_two", C)) {
            reportUnreliableZeroCheck(Condition, C);
            return;
          }
        }
      } else if (isZeroIntExpr(R, C)) {
        // Mirror for LHS
        if (const MemRegion *MR = getVarRegion(L, C)) {
          if (MR->getBaseRegion() && State->get<RoundupResMap>(MR->getBaseRegion())) {
            reportUnreliableZeroCheck(Condition, C);
            return;
          }
        }
        if (const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(L)) {
          if (ExprHasName(CE, "roundup_pow_of_two", C)) {
            reportUnreliableZeroCheck(Condition, C);
            return;
          }
        }
      }
    }
  }

  // No changes to state necessary if nothing detected.
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unreliable zero-checks on results of roundup_pow_of_two() on 32-bit targets",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
