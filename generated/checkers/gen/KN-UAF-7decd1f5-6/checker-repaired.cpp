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

using namespace clang;
using namespace ento;
using namespace taint;

// ================= Program States =================
REGISTER_SET_WITH_PROGRAMSTATE(FreedUnderUnlockSet, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(InUnlockedRegion, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind, check::Location> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Use-after-free after unlocked close", "Memory Safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper predicates
  static bool isSpinUnlock(const CallEvent &Call, CheckerContext &C);
  static bool isSpinLock(const CallEvent &Call, CheckerContext &C);
  static bool isKnownFreeFunc(const CallEvent &Call, CheckerContext &C,
                              llvm::SmallVectorImpl<unsigned> &FreedParamIdxs);

  static const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C);
  void reportUAF(const Stmt *AccessS, CheckerContext &C) const;
};

// ---------------- Helper Implementations ----------------

bool SAGenTestChecker::isSpinUnlock(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "spin_unlock_bh", C) || ExprHasName(E, "spin_unlock", C);
}

bool SAGenTestChecker::isSpinLock(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "spin_lock_bh", C) || ExprHasName(E, "spin_lock", C);
}

// Known-freeing function table tailored for the target bug
bool SAGenTestChecker::isKnownFreeFunc(const CallEvent &Call, CheckerContext &C,
                                       llvm::SmallVectorImpl<unsigned> &FreedParamIdxs) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;

  // For this pattern, mptcp_close_ssk(sk, ssk, subflow) may free 'subflow' (arg index 2)
  if (ExprHasName(E, "mptcp_close_ssk", C)) {
    FreedParamIdxs.push_back(2);
    return true;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

void SAGenTestChecker::reportUAF(const Stmt *AccessS, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use-after-free after close under unlocked region", N);
  if (AccessS)
    R->addRange(AccessS->getSourceRange());
  C.emitReport(std::move(R));
}

// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Track unlocked window
  if (isSpinUnlock(Call, C)) {
    State = State->set<InUnlockedRegion>(true);
    Changed = true;
  } else if (isSpinLock(Call, C)) {
    State = State->set<InUnlockedRegion>(false);
    Changed = true;
  }

  // If currently in the unlocked window, mark pointer variables passed to
  // known-freeing functions as possibly freed under unlock.
  bool InUnlocked = State->get<InUnlockedRegion>();

  llvm::SmallVector<unsigned, 4> FreedIdxs;
  if (InUnlocked && isKnownFreeFunc(Call, C, FreedIdxs)) {
    for (unsigned Idx : FreedIdxs) {
      if (Idx >= Call.getNumArgs())
        continue;
      const Expr *ArgE = Call.getArgExpr(Idx);
      const MemRegion *MR = getBaseRegionFromExpr(ArgE, C);
      if (!MR)
        continue;
      State = State->add<FreedUnderUnlockSet>(MR);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If a pointer variable that we tracked as "freed under unlock" is reassigned,
  // remove it from the set to avoid stale reports.
  if (const MemRegion *LReg = Loc.getAsRegion()) {
    LReg = LReg->getBaseRegion();
    if (LReg) {
      auto Set = State->get<FreedUnderUnlockSet>();
      if (Set.contains(LReg)) {
        State = State->remove<FreedUnderUnlockSet>(LReg);
        C.addTransition(State);
      }
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad || !S)
    return;

  ProgramStateRef State = C.getState();
  // Only warn after the lock is reacquired (i.e., not in the unlocked window)
  if (State->get<InUnlockedRegion>())
    return;

  const MemRegion *BaseVarReg = nullptr;

  // Focus on dereference patterns: 'ptr->field', '*ptr', 'ptr[i]'
  if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    if (!ME->isArrow())
      return; // Only track '->', not '.'
    const Expr *Base = ME->getBase();
    BaseVarReg = getBaseRegionFromExpr(Base, C);
  } else if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() != UO_Deref)
      return;
    const Expr *Base = UO->getSubExpr();
    BaseVarReg = getBaseRegionFromExpr(Base, C);
  } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase();
    BaseVarReg = getBaseRegionFromExpr(Base, C);
  } else {
    // Other expressions are not targeted.
    return;
  }

  if (!BaseVarReg)
    return;

  auto Set = State->get<FreedUnderUnlockSet>();
  if (Set.contains(BaseVarReg)) {
    reportUAF(S, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free when an object may be freed by a close function between spin_unlock and spin_lock, then accessed after lock",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
