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
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state customizations

// Map: return Symbol of wait_for_completion_timeout() -> context MemRegion (container of struct with completion)
REGISTER_MAP_WITH_PROGRAMSTATE(WaitRetSymToContainer, SymbolRef, const MemRegion*)

// Set: context MemRegions that are in the timeout branch (wait_for_completion_timeout returned 0)
REGISTER_SET_WITH_PROGRAMSTATE(TimeoutContainers, const MemRegion*)

// Set: context MemRegions whose work items were enqueued/scheduled
REGISTER_SET_WITH_PROGRAMSTATE(EnqueuedWorkContainers, const MemRegion*)

// Set: context MemRegions whose work items have been canceled/flushed and are safe to free
REGISTER_SET_WITH_PROGRAMSTATE(SafeToFreeContainers, const MemRegion*)

// Map: pointer aliasing (lhs region -> rhs region it aliases)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind,
        eval::Assume> {

   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Work context freed on timeout", "Concurrency")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

   private:

      // Helpers to recognize functions
      bool isWaitTimeout(const CallEvent &Call, CheckerContext &C) const;
      bool isWorkQueueSubmit(const CallEvent &Call, unsigned &WorkArgIndex, CheckerContext &C) const;
      bool isWorkCancelOrFlush(const CallEvent &Call, CheckerContext &C) const;
      bool isFreeCall(const CallEvent &Call, CheckerContext &C) const;

      // Extract context (container) region from common expressions
      const MemRegion *getContextRegionFromMemberAddressArg(const Expr *Arg, CheckerContext &C) const;
      const MemRegion *getContextRegionFromExpr(const Expr *E, CheckerContext &C) const;

      // Alias resolution
      const MemRegion *resolveAlias(const MemRegion *R, ProgramStateRef State) const;

      // Reporting
      void reportUAF(const CallEvent &Call, CheckerContext &C, const MemRegion *CtxR) const;
};

// Implementation

bool SAGenTestChecker::isWaitTimeout(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "wait_for_completion_timeout", C);
}

bool SAGenTestChecker::isWorkQueueSubmit(const CallEvent &Call, unsigned &WorkArgIndex, CheckerContext &C) const {
  WorkArgIndex = 0;
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;

  if (ExprHasName(E, "schedule_work", C)) { WorkArgIndex = 0; return true; }
  if (ExprHasName(E, "queue_work_on", C)) { WorkArgIndex = 2; return true; }
  if (ExprHasName(E, "queue_work", C)) { WorkArgIndex = 1; return true; }
  if (ExprHasName(E, "queue_delayed_work_on", C)) { WorkArgIndex = 2; return true; }
  if (ExprHasName(E, "queue_delayed_work", C)) { WorkArgIndex = 1; return true; }
  if (ExprHasName(E, "schedule_delayed_work_on", C)) { WorkArgIndex = 1; return true; }
  if (ExprHasName(E, "schedule_delayed_work", C)) { WorkArgIndex = 0; return true; }

  return false;
}

bool SAGenTestChecker::isWorkCancelOrFlush(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "cancel_work_sync", C) ||
         ExprHasName(E, "cancel_delayed_work_sync", C) ||
         ExprHasName(E, "flush_work", C) ||
         ExprHasName(E, "flush_delayed_work", C);
}

bool SAGenTestChecker::isFreeCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "kfree", C) || ExprHasName(E, "kvfree", C) || ExprHasName(E, "vfree", C);
}

const MemRegion *SAGenTestChecker::getContextRegionFromMemberAddressArg(const Expr *Arg, CheckerContext &C) const {
  if (!Arg) return nullptr;

  const Expr *AE = Arg;
  // Expect &ctx->member
  if (const auto *UO = dyn_cast<UnaryOperator>(AE)) {
    if (UO->getOpcode() == UO_AddrOf) {
      const Expr *Sub = UO->getSubExpr();
      if (const auto *ME = dyn_cast<MemberExpr>(Sub)) {
        const Expr *BaseE = ME->getBase();
        if (!BaseE) return nullptr;
        const MemRegion *BR = getMemRegionFromExpr(BaseE, C);
        if (!BR) return nullptr;
        BR = BR->getBaseRegion();
        return BR;
      }
    }
  }
  return nullptr;
}

const MemRegion *SAGenTestChecker::getContextRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *R = getMemRegionFromExpr(E, C);
  if (!R) return nullptr;
  return R->getBaseRegion();
}

const MemRegion *SAGenTestChecker::resolveAlias(const MemRegion *R, ProgramStateRef State) const {
  if (!R) return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break; // cycle
    const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur);
    if (!NextPtr) break;
    const MemRegion *Next = *NextPtr;
    Cur = Next ? Next->getBaseRegion() : nullptr;
  }
  return Cur;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track wait_for_completion_timeout: map its return symbol to the context (container) region.
  if (isWaitTimeout(Call, C)) {
    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *CtxR = getContextRegionFromMemberAddressArg(Arg0, C);
    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (CtxR && RetSym) {
      State = State->set<WaitRetSymToContainer>(RetSym, CtxR->getBaseRegion());
      C.addTransition(State);
      return;
    }
  }

  // Track work submissions
  unsigned WorkIdx = 0;
  if (isWorkQueueSubmit(Call, WorkIdx, C)) {
    if (Call.getNumArgs() > WorkIdx) {
      const Expr *WArg = Call.getArgExpr(WorkIdx);
      const MemRegion *CtxR = getContextRegionFromMemberAddressArg(WArg, C);
      if (CtxR) {
        State = State->add<EnqueuedWorkContainers>(CtxR->getBaseRegion());
        C.addTransition(State);
        return;
      }
    }
  }

  // Track work cancel/flush => safe to free
  if (isWorkCancelOrFlush(Call, C)) {
    if (Call.getNumArgs() > 0) {
      const Expr *WArg = Call.getArgExpr(0);
      const MemRegion *CtxR = getContextRegionFromMemberAddressArg(WArg, C);
      if (CtxR) {
        CtxR = CtxR->getBaseRegion();
        State = State->add<SafeToFreeContainers>(CtxR);
        State = State->remove<EnqueuedWorkContainers>(CtxR);
        C.addTransition(State);
        return;
      }
    }
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  SymbolRef SE = Cond.getAsSymbol();
  if (!SE)
    return State;

  auto Map = State->get<WaitRetSymToContainer>();
  if (Map.isEmpty())
    return State;

  // For each tracked wait return symbol, if the current condition references it,
  // decide if this assumption corresponds to "return == 0" or "return != 0".
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    SymbolRef RetSym = I->first;
    const MemRegion *CtxR = I->second;

    bool MentionsRetSym = false;
    bool ZeroBranch = false;
    bool NonZeroBranch = false;

    // Helper to unwrap casts
    auto UnwrapCasts = [](const SymExpr *S) -> const SymExpr * {
      const SymExpr *Cur = S;
      while (const auto *CE = dyn_cast<SymbolCast>(Cur))
        Cur = CE->getOperand();
      return Cur;
    };

    if (SE == RetSym) {
      MentionsRetSym = true;
      ZeroBranch = !Assumption;
      NonZeroBranch = Assumption;
    } else if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
      const SymExpr *Inner = UnwrapCasts(SIE->getLHS());
      if (Inner == RetSym && SIE->getRHS().isZero()) {
        MentionsRetSym = true;
        BinaryOperator::Opcode Op = SIE->getOpcode();
        if (Op == BO_EQ) {
          ZeroBranch = Assumption;
          NonZeroBranch = !Assumption;
        } else if (Op == BO_NE) {
          ZeroBranch = !Assumption;
          NonZeroBranch = Assumption;
        }
      }
    } else if (const auto *ISE = dyn_cast<IntSymExpr>(SE)) {
      const SymExpr *Inner = UnwrapCasts(ISE->getRHS());
      if (Inner == RetSym && ISE->getLHS().isZero()) {
        MentionsRetSym = true;
        BinaryOperator::Opcode Op = ISE->getOpcode();
        if (Op == BO_EQ) {
          ZeroBranch = Assumption;
          NonZeroBranch = !Assumption;
        } else if (Op == BO_NE) {
          ZeroBranch = !Assumption;
          NonZeroBranch = Assumption;
        }
      }
    }

    if (!MentionsRetSym)
      continue;

    if (ZeroBranch) {
      State = State->add<TimeoutContainers>(CtxR->getBaseRegion());
    } else if (NonZeroBranch) {
      State = State->remove<TimeoutContainers>(CtxR->getBaseRegion());
    }
  }

  return State;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeCall(Call, C))
    return;

  ProgramStateRef State = C.getState();

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  const MemRegion *PtrR = getContextRegionFromExpr(Arg0, C);
  if (!PtrR)
    return;
  PtrR = PtrR->getBaseRegion();

  const MemRegion *Resolved = resolveAlias(PtrR, State);
  if (!Resolved)
    Resolved = PtrR;

  bool TimedOut = State->contains<TimeoutContainers>(Resolved);
  bool Enqueued = State->contains<EnqueuedWorkContainers>(Resolved);
  bool Safe = State->contains<SafeToFreeContainers>(Resolved);

  if (TimedOut && Enqueued && !Safe) {
    reportUAF(Call, C, Resolved);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS) {
    C.addTransition(State);
    return;
  }
  LHS = LHS->getBaseRegion();

  if (const MemRegion *RHS = Val.getAsRegion()) {
    RHS = RHS->getBaseRegion();
    if (RHS) {
      // Track alias in both directions
      State = State->set<PtrAliasMap>(LHS, RHS);
      State = State->set<PtrAliasMap>(RHS, LHS);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportUAF(const CallEvent &Call, CheckerContext &C, const MemRegion *CtxR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing work context after completion timeout; worker may still use it (possible UAF).", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect freeing work context after wait_for_completion_timeout() timeout while work may still run",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
