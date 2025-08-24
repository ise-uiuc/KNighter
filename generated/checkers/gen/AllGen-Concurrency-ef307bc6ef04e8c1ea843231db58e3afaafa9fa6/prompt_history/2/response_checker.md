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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/Casting.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_SET_WITH_PROGRAMSTATE(LockSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(JustUnlockedSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
  check::PostCall,
  check::Bind,
  check::EndFunction
> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unlocked clear of shared pointer", "Concurrency")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helpers
  bool calleeNameContains(const CallEvent &Call, StringRef Needle, CheckerContext &C) const;
  bool isSpinLockCall(const CallEvent &Call, CheckerContext &C) const;
  bool isSpinUnlockCall(const CallEvent &Call, CheckerContext &C) const;
  const MemRegion *lockArgRegion(const CallEvent &Call, CheckerContext &C) const;

  bool isAssigningUrbHcprivNull(const Stmt *S, SVal Val, CheckerContext &C,
                                SourceRange &HighlightRange) const;

  ProgramStateRef clearJustUnlocked(ProgramStateRef State) const {
    return State->remove<JustUnlockedSet>();
  }
};

bool SAGenTestChecker::calleeNameContains(const CallEvent &Call, StringRef Needle,
                                          CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, Needle, C);
}

bool SAGenTestChecker::isSpinLockCall(const CallEvent &Call, CheckerContext &C) const {
  // Matches spin_lock, spin_lock_irqsave, spin_lock_bh, etc.
  return calleeNameContains(Call, "spin_lock", C) &&
         !calleeNameContains(Call, "spin_unlock", C);
}

bool SAGenTestChecker::isSpinUnlockCall(const CallEvent &Call, CheckerContext &C) const {
  // Matches spin_unlock, spin_unlock_irqrestore, spin_unlock_bh, etc.
  return calleeNameContains(Call, "spin_unlock", C);
}

const MemRegion *SAGenTestChecker::lockArgRegion(const CallEvent &Call, CheckerContext &C) const {
  if (Call.getNumArgs() == 0)
    return nullptr;
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

bool SAGenTestChecker::isAssigningUrbHcprivNull(const Stmt *S, SVal Val,
                                                CheckerContext &C,
                                                SourceRange &HighlightRange) const {
  if (!S) return false;

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO)
    BO = findSpecificTypeInChildren<BinaryOperator>(S);
  if (!BO)
    return false;
  if (BO->getOpcode() != BO_Assign)
    return false;

  const Expr *LHS = BO->getLHS();
  if (!LHS) return false;
  const Expr *RHS = BO->getRHS();
  if (!RHS) return false;

  const MemberExpr *ME = dyn_cast<MemberExpr>(LHS->IgnoreParenCasts());
  if (!ME)
    return false;

  // Check the member name is 'hcpriv'
  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast_or_null<FieldDecl>(VD);
  if (!FD)
    return false;
  if (FD->getName() != "hcpriv")
    return false;

  // Check base expression text contains "urb" (focus on urb->hcpriv pattern)
  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return false;
  if (!ExprHasName(BaseE, "urb", C))
    return false;

  // Check RHS is NULL/0
  bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                              Expr::NPC_ValueDependentIsNull);
  if (!RHSIsNull) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, RHS, C)) {
      RHSIsNull = EvalRes == 0;
    } else {
      // Try via SVal if constant
      if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
        RHSIsNull = CI->getValue() == 0;
      }
    }
  }
  if (!RHSIsNull)
    return false;

  HighlightRange = ME->getSourceRange();
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isSpinLockCall(Call, C)) {
    if (const MemRegion *LR = lockArgRegion(Call, C)) {
      State = State->add<LockSet>(LR);
      // entering protected region, clear any "just unlocked" marks
      State = clearJustUnlocked(State);
      C.addTransition(State);
      return;
    }
  }

  if (isSpinUnlockCall(Call, C)) {
    if (const MemRegion *LR = lockArgRegion(Call, C)) {
      State = State->remove<LockSet>(LR);
      State = State->add<JustUnlockedSet>(LR);
      C.addTransition(State);
      return;
    }
  }

  // Any other call clears the "just unlocked" window.
  const JustUnlockedSetTy *JU = State->get<JustUnlockedSet>();
  if (JU && !JU->isEmpty()) {
    State = clearJustUnlocked(State);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const JustUnlockedSetTy *JU = State->get<JustUnlockedSet>();

  bool HadJustUnlocked = (JU && !JU->isEmpty());
  bool Reported = false;

  if (HadJustUnlocked) {
    // We only consider immediate next store after spin_unlock.
    // Ensure the destination is the urb->hcpriv field and RHS is NULL.
    SourceRange SR;
    if (isAssigningUrbHcprivNull(S, Val, C, SR)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (N) {
        auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "urb->hcpriv cleared after spin_unlock; move assignment under the lock", N);
        if (SR.isValid())
          R->addRange(SR);
        C.emitReport(std::move(R));
      }
      Reported = true;
    }
  }

  // Regardless of whether we reported or not, the "just unlocked" window
  // should be cleared on the first subsequent bind to keep the window short.
  if (HadJustUnlocked) {
    State = clearJustUnlocked(State);
    C.addTransition(State);
  } else if (Reported) {
    // Defensive: in unusual flows, still ensure state transition if we reported.
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->remove<LockSet>();
  State = State->remove<JustUnlockedSet>();
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects urb->hcpriv = NULL immediately after spin_unlock (move under lock)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
