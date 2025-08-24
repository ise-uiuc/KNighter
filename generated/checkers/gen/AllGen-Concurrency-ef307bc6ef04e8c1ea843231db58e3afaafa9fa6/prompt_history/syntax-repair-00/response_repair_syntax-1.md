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
#include "llvm/ADT/ImmutableSet.h"
#include <memory>
#include <initializer_list>

using namespace clang;
using namespace ento;
using namespace taint;

//====================== Program state ======================

using LockSet = llvm::ImmutableSet<const MemRegion *>;
using ObjSet  = llvm::ImmutableSet<const MemRegion *>;

REGISTER_TRAIT_WITH_PROGRAMSTATE(HeldLocks, LockSet)
REGISTER_MAP_WITH_PROGRAMSTATE(LockToObjSetMap, const MemRegion*, ObjSet)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LastUnlockedLock, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(ObjSetTrait, ObjSet)

//====================== Helpers ============================

static bool isOneOf(StringRef S, std::initializer_list<StringRef> Names) {
  for (auto &N : Names)
    if (S == N) return true;
  return false;
}

static bool isLockAcquire(const CallEvent &Call, CheckerContext &C) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Name = ID->getName();
    return isOneOf(Name, {"spin_lock", "spin_lock_irqsave", "spin_lock_bh", "spin_lock_irq"});
  }
  // Fallback to textual check
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "spin_lock_irqsave", C) ||
         ExprHasName(E, "spin_lock_irq", C) ||
         ExprHasName(E, "spin_lock_bh", C) ||
         ExprHasName(E, "spin_lock", C);
}

static bool isLockRelease(const CallEvent &Call, CheckerContext &C) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Name = ID->getName();
    return isOneOf(Name, {"spin_unlock", "spin_unlock_irqrestore", "spin_unlock_bh", "spin_unlock_irq"});
  }
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "spin_unlock_irqrestore", C) ||
         ExprHasName(E, "spin_unlock_irq", C) ||
         ExprHasName(E, "spin_unlock_bh", C) ||
         ExprHasName(E, "spin_unlock", C);
}

static const MemRegion *getLockRegionFromCall(const CallEvent &Call, CheckerContext &C) {
  if (Call.getNumArgs() < 1)
    return nullptr;
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return nullptr;
  const MemRegion *R = getMemRegionFromExpr(Arg0, C);
  if (!R)
    return nullptr;
  return R->getBaseRegion();
}

static ProgramStateRef addHeldLock(ProgramStateRef State, const MemRegion *Lock, CheckerContext &C) {
  if (!Lock) return State;
  LockSet Cur = State->get<HeldLocks>();
  LockSet::Factory &F = State->get_context<HeldLocks>();
  Cur = F.add(Cur, Lock);
  State = State->set<HeldLocks>(Cur);
  // When we start holding a lock again, the "just unlocked" window is over.
  State = State->set<LastUnlockedLock>(nullptr);
  return State;
}

static ProgramStateRef removeHeldLock(ProgramStateRef State, const MemRegion *Lock) {
  if (!Lock) return State;
  LockSet Cur = State->get<HeldLocks>();
  LockSet::Factory &F = State->get_context<HeldLocks>();
  Cur = F.remove(Cur, Lock);
  State = State->set<HeldLocks>(Cur);
  return State;
}

static bool objSetContains(const ObjSet &S, const MemRegion *R) {
  for (auto It = S.begin(); It != S.end(); ++It) {
    if (*It == R)
      return true;
  }
  return false;
}

// Record that "ObjR" is used while holding each lock in HeldLocks.
static ProgramStateRef recordObjUseUnderHeldLocks(ProgramStateRef State,
                                                  const Expr *ArgE,
                                                  CheckerContext &C) {
  if (!ArgE)
    return State;
  LockSet Locks = State->get<HeldLocks>();
  if (Locks.isEmpty())
    return State;

  const MemRegion *ObjR = nullptr;

  // If it's a member access, prefer to use the base object's region.
  if (const auto *ME = dyn_cast<MemberExpr>(ArgE->IgnoreParenCasts())) {
    const Expr *BaseE = ME->getBase();
    ObjR = getMemRegionFromExpr(BaseE, C);
  } else {
    ObjR = getMemRegionFromExpr(ArgE, C);
  }

  if (!ObjR)
    return State;
  ObjR = ObjR->getBaseRegion();
  if (!ObjR)
    return State;

  ObjSet::Factory &OF = State->get_context<ObjSetTrait>();
  for (auto LI = Locks.begin(); LI != Locks.end(); ++LI) {
    const MemRegion *LockR = *LI;
    if (!LockR) continue;
    const ObjSet *CurPtr = State->get<LockToObjSetMap>(LockR);
    ObjSet Cur = CurPtr ? *CurPtr : OF.getEmptySet();
    if (!objSetContains(Cur, ObjR)) {
      Cur = OF.add(Cur, ObjR);
      State = State->set<LockToObjSetMap>(LockR, Cur);
    }
  }
  return State;
}

static bool isZeroSVal(SVal V) {
  if (auto CI = V.getAs<nonloc::ConcreteInt>())
    return CI->getValue() == 0;
  if (auto LCI = V.getAs<loc::ConcreteInt>())
    return LCI->getValue() == 0;
  return false;
}

static bool isPointerFieldAssignmentToNull(const Stmt *S, SVal Loc, SVal Val,
                                           CheckerContext &C,
                                           const BinaryOperator *&OutBO,
                                           const MemberExpr *&OutME) {
  OutBO = nullptr;
  OutME = nullptr;

  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const auto *ME = dyn_cast<MemberExpr>(LHS);
  if (!ME)
    return false;

  // We focus on pointer field like obj->field.
  if (!ME->isArrow())
    return false;

  QualType FieldTy = ME->getType();
  if (FieldTy.isNull() || !FieldTy->isPointerType())
    return false;

  bool IsNull = isZeroSVal(Val);
  if (!IsNull) {
    // Try evaluate RHS constant int == 0
    llvm::APSInt IntV;
    if (EvaluateExprToInt(IntV, BO->getRHS(), C))
      IsNull = (IntV == 0);
  }
  if (!IsNull)
    return false;

  OutBO = BO;
  OutME = ME;
  return true;
}

static const MemRegion *getBaseObjectRegionFromLHS(const BinaryOperator *BO,
                                                   CheckerContext &C) {
  if (!BO) return nullptr;
  const auto *ME = dyn_cast<MemberExpr>(BO->getLHS()->IgnoreParenCasts());
  if (!ME) return nullptr;
  const Expr *BaseE = ME->getBase();
  if (!BaseE) return nullptr;
  const MemRegion *R = getMemRegionFromExpr(BaseE, C);
  if (!R) return nullptr;
  return R->getBaseRegion();
}

//====================== Checker ============================

namespace {

class SAGenTestChecker
  : public Checker<check::BeginFunction,
                   check::PreCall,
                   check::PostCall,
                   check::Location,
                   check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Pointer field NULLed after unlock", "Concurrency")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  void reportIssue(const BinaryOperator *BO, CheckerContext &C) const;
};

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Initialize/clear per-function state.
  State = State->set<HeldLocks>(State->get_context<HeldLocks>().getEmptySet());
  State = State->set<LastUnlockedLock>(nullptr);

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If this is a non-unlock call and we have a pending "just unlocked" mark, clear it.
  if (State->get<LastUnlockedLock>() && !isLockRelease(Call, C) && !isLockAcquire(Call, C)) {
    State = State->set<LastUnlockedLock>(nullptr);
  }

  // Handle lock acquire
  if (isLockAcquire(Call, C)) {
    if (const MemRegion *LockR = getLockRegionFromCall(Call, C)) {
      State = addHeldLock(State, LockR, C);
    }
    C.addTransition(State);
    return;
  }

  // While locks are held, record any object/pointer arguments used inside the critical section.
  if (!State->get<HeldLocks>().isEmpty()) {
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      const Expr *ArgE = Call.getArgExpr(i);
      State = recordObjUseUnderHeldLocks(State, ArgE, C);
    }
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Handle lock release
  if (isLockRelease(Call, C)) {
    const MemRegion *LockR = getLockRegionFromCall(Call, C);
    State = removeHeldLock(State, LockR);
    // Mark the last unlocked lock to detect the immediate next assignment.
    State = State->set<LastUnlockedLock>(LockR);
    C.addTransition(State);
    return;
  }

  // Any other call after unlock clears the "just unlocked" mark to keep window small.
  if (State->get<LastUnlockedLock>()) {
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (State->get<HeldLocks>().isEmpty())
    return;

  // When under a lock, if the location is part of a MemberExpr, record the base object.
  const MemberExpr *ME = findSpecificTypeInParents<MemberExpr>(S, C);
  if (!ME)
    return;

  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return;

  State = recordObjUseUnderHeldLocks(State, BaseE, C);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *JustUnlocked = State->get<LastUnlockedLock>();
  // We only care about the immediate next assignment after an unlock, and only when no lock is held.
  if (JustUnlocked && State->get<HeldLocks>().isEmpty()) {
    const BinaryOperator *BO = nullptr;
    const MemberExpr *ME = nullptr;

    if (isPointerFieldAssignmentToNull(S, Loc, Val, C, BO, ME)) {
      // Determine the "object" whose field is being NULLed.
      const MemRegion *ObjR = getBaseObjectRegionFromLHS(BO, C);
      if (ObjR) {
        // Check if this object was used under the same lock earlier in this path.
        const ObjSet *UsedObjsPtr = State->get<LockToObjSetMap>(JustUnlocked);
        if (UsedObjsPtr && objSetContains(*UsedObjsPtr, ObjR)) {
          reportIssue(BO, C);
        }
      }
    }
  }

  // Regardless, clear the "just unlocked" marker after the first bind we see.
  if (JustUnlocked) {
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportIssue(const BinaryOperator *BO, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Pointer field set to NULL after unlocking; may race with readers under the lock", N);
  if (BO)
    R->addRange(BO->getLHS()->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects setting lock-protected pointer fields to NULL immediately after unlocking",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
