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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(RoundupResMap, const MemRegion *, const Expr *)

namespace {

class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Misuse of roundup_pow_of_two overflow check", "API Misuse")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:

      const Expr *getRHSOfAssignmentOrInit(const Stmt *S) const;
      bool isZeroExpr(const Expr *E, CheckerContext &C) const;
      bool isRoundupExpr(const Expr *E, CheckerContext &C) const;
      void report(const Stmt *Condition, CheckerContext &C) const;
};

const Expr *SAGenTestChecker::getRHSOfAssignmentOrInit(const Stmt *S) const {
  if (!S)
    return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      return BO->getRHS();
  }

  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    if (DS->isSingleDecl()) {
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (VD->hasInit())
          return VD->getInit();
      }
    }
  }

  return nullptr;
}

bool SAGenTestChecker::isZeroExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E->IgnoreParenImpCasts(), C)) {
    return Res == 0;
  }
  return false;
}

bool SAGenTestChecker::isRoundupExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  // Use source text presence to cover both calls and macro-like expansions.
  return ExprHasName(E, "roundup_pow_of_two", C);
}

void SAGenTestChecker::report(const Stmt *Condition, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Do not detect overflow by testing roundup_pow_of_two(x) == 0; on 32-bit, check x <= (1UL << 31) before calling.",
      N);
  if (Condition)
    R->addRange(Condition->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstR = Loc.getAsRegion();
  if (!DstR)
    return;
  DstR = DstR->getBaseRegion();
  if (!DstR)
    return;

  const Expr *RHSRaw = getRHSOfAssignmentOrInit(S);
  if (!RHSRaw) {
    // Not an assignment or init we care about; clear any prior tag.
    if (State->contains<RoundupResMap>(DstR)) {
      State = State->remove<RoundupResMap>(DstR);
      C.addTransition(State);
    }
    return;
  }

  // Case 1: RHS is roundup_pow_of_two(...) (or macro-expands to it).
  if (isRoundupExpr(RHSRaw, C)) {
    // Try to store the argument for better context if it's a real call.
    const Expr *Stored = nullptr;
    if (const auto *CE = dyn_cast<CallExpr>(RHSRaw->IgnoreParenImpCasts())) {
      if (CE->getNumArgs() > 0)
        Stored = CE->getArg(0);
    }
    // Fallback to store RHS itself if we didn't find a clean argument.
    if (!Stored)
      Stored = RHSRaw;

    State = State->set<RoundupResMap>(DstR, Stored);
    C.addTransition(State);
    return;
  }

  // Case 2: Propagate tag on simple copies: dest = src;
  if (const MemRegion *SrcR = getMemRegionFromExpr(RHSRaw, C)) {
    SrcR = SrcR->getBaseRegion();
    if (SrcR) {
      if (const Expr *const *Tagged = State->get<RoundupResMap>(SrcR)) {
        State = State->set<RoundupResMap>(DstR, *Tagged);
        C.addTransition(State);
        return;
      }
    }
  }

  // Default: clear any prior tag for destination.
  if (State->contains<RoundupResMap>(DstR)) {
    State = State->remove<RoundupResMap>(DstR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Only warn on 32-bit unsigned long targets.
  const ASTContext &ACtx = C.getASTContext();
  unsigned ULWidth = ACtx.getIntWidth(ACtx.UnsignedLongTy);
  if (ULWidth != 32)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  const Expr *CondNoCasts = CondE->IgnoreParenImpCasts();

  // Pattern P2 first: direct zero-check on roundup expression.
  if (const auto *UO = dyn_cast<UnaryOperator>(CondNoCasts)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      if (isRoundupExpr(Sub, C)) {
        report(Condition, C);
        return;
      }
      // Also handle: if (!n) where n was assigned from roundup_pow_of_two
      if (const MemRegion *MR = getMemRegionFromExpr(Sub, C)) {
        MR = MR->getBaseRegion();
        if (MR) {
          if (State->get<RoundupResMap>(MR)) {
            report(Condition, C);
            return;
          }
        }
      }
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondNoCasts)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS();
      const Expr *R = BO->getRHS();

      bool LIsZero = isZeroExpr(L, C);
      bool RIsZero = isZeroExpr(R, C);

      // Direct check on roundup expression: roundup_pow_of_two(x) == 0
      if ((isRoundupExpr(L, C) && RIsZero) || (isRoundupExpr(R, C) && LIsZero)) {
        report(Condition, C);
        return;
      }

      // Check variable tagged by prior assignment: n == 0
      if (RIsZero) {
        if (const MemRegion *MR = getMemRegionFromExpr(L, C)) {
          MR = MR->getBaseRegion();
          if (MR && State->get<RoundupResMap>(MR)) {
            report(Condition, C);
            return;
          }
        }
      } else if (LIsZero) {
        if (const MemRegion *MR = getMemRegionFromExpr(R, C)) {
          MR = MR->getBaseRegion();
          if (MR && State->get<RoundupResMap>(MR)) {
            report(Condition, C);
            return;
          }
        }
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Warn when using roundup_pow_of_two(x) == 0 to detect overflow; check x <= (1UL << 31) before calling",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
