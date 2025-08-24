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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_SET_WITH_PROGRAMSTATE(HeldLocks, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(ProtectedFieldToLock, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Location, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Inconsistent locking", "Concurrency")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool isSpinLock(const CallEvent &Call, CheckerContext &C);
      static bool isSpinUnlock(const CallEvent &Call, CheckerContext &C);
      static const MemRegion* getLockRegionFromArg(const CallEvent &Call, CheckerContext &C);
      static const MemRegion* getFieldRegionFromExpr(const Expr *E, CheckerContext &C);
      static const MemRegion* getFieldRegionFromLoc(const MemRegion *MR);
      static const MemRegion* getOnlyHeldLock(ProgramStateRef State);
      static bool isNullAssigned(const Stmt *S, CheckerContext &C);

      static void recordFieldUnderOnlyLock(const Expr *ArgE, CheckerContext &C);
      static void recordFieldUnderOnlyLockFromLoc(SVal Loc, CheckerContext &C);
};

bool SAGenTestChecker::isSpinLock(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "spin_lock", C) ||
         ExprHasName(E, "spin_lock_irqsave", C) ||
         ExprHasName(E, "spin_lock_irq", C) ||
         ExprHasName(E, "spin_lock_bh", C);
}

bool SAGenTestChecker::isSpinUnlock(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "spin_unlock", C) ||
         ExprHasName(E, "spin_unlock_irqrestore", C) ||
         ExprHasName(E, "spin_unlock_irq", C) ||
         ExprHasName(E, "spin_unlock_bh", C);
}

const MemRegion* SAGenTestChecker::getFieldRegionFromLoc(const MemRegion *MR) {
  if (!MR) return nullptr;
  // Walk up to find a FieldRegion
  const MemRegion *Cur = MR;
  while (Cur) {
    if (isa<FieldRegion>(Cur))
      return Cur;
    if (const auto *SR = dyn_cast<SubRegion>(Cur))
      Cur = SR->getSuperRegion();
    else
      break;
  }
  return nullptr;
}

const MemRegion* SAGenTestChecker::getFieldRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;

  // Try directly from the expression
  if (const MemRegion *MR = getMemRegionFromExpr(E, C)) {
    if (const MemRegion *FR = getFieldRegionFromLoc(MR))
      return FR;
  }

  // Try to find a MemberExpr child and get its region
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (const MemRegion *MR2 = getMemRegionFromExpr(ME, C)) {
      if (const MemRegion *FR2 = getFieldRegionFromLoc(MR2))
        return FR2;
    }
  }
  return nullptr;
}

const MemRegion* SAGenTestChecker::getLockRegionFromArg(const CallEvent &Call, CheckerContext &C) {
  if (Call.getNumArgs() < 1)
    return nullptr;

  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return nullptr;

  // If it's &obj->lock, peel off the address-of to get the underlying object
  if (const auto *UO = dyn_cast<UnaryOperator>(ArgE)) {
    if (UO->getOpcode() == UO_AddrOf)
      ArgE = UO->getSubExpr();
  }

  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;

  // Always use base region as per suggestions
  MR = MR->getBaseRegion();
  return MR;
}

const MemRegion* SAGenTestChecker::getOnlyHeldLock(ProgramStateRef State) {
  auto Set = State->get<HeldLocks>();
  const MemRegion *Only = nullptr;
  unsigned Count = 0;
  for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
    Only = *I;
    ++Count;
    if (Count > 1)
      return nullptr;
  }
  return (Count == 1) ? Only : nullptr;
}

bool SAGenTestChecker::isNullAssigned(const Stmt *S, CheckerContext &C) {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO)
    return false;
  if (BO->getOpcode() != BO_Assign)
    return false;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return false;

  // Try to evaluate as integer
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, RHS, C)) {
    if (Val == 0)
      return true;
  }

  // Fallback: check for null pointer constant
  if (RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

  return false;
}

void SAGenTestChecker::recordFieldUnderOnlyLock(const Expr *ArgE, CheckerContext &C) {
  if (!ArgE)
    return;
  ProgramStateRef State = C.getState();
  const MemRegion *OnlyLock = getOnlyHeldLock(State);
  if (!OnlyLock)
    return;

  const MemRegion *FR = getFieldRegionFromExpr(ArgE, C);
  if (!FR)
    return;

  // Use the base region of the field as key to follow the suggestion
  const MemRegion *FieldKey = FR->getBaseRegion();
  if (!FieldKey)
    return;

  State = State->set<ProtectedFieldToLock>(FieldKey, OnlyLock);
  C.addTransition(State);
}

void SAGenTestChecker::recordFieldUnderOnlyLockFromLoc(SVal Loc, CheckerContext &C) {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const MemRegion *FR = getFieldRegionFromLoc(MR);
  if (!FR)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *OnlyLock = getOnlyHeldLock(State);
  if (!OnlyLock)
    return;

  const MemRegion *FieldKey = FR->getBaseRegion();
  if (!FieldKey)
    return;

  State = State->set<ProtectedFieldToLock>(FieldKey, OnlyLock);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Update held locks
  if (isSpinLock(Call, C)) {
    if (const MemRegion *LockReg = getLockRegionFromArg(Call, C)) {
      State = State->add<HeldLocks>(LockReg);
      C.addTransition(State);
    }
    return;
  }

  if (isSpinUnlock(Call, C)) {
    if (const MemRegion *LockReg = getLockRegionFromArg(Call, C)) {
      State = State->remove<HeldLocks>(LockReg);
      C.addTransition(State);
    }
    return;
  }

  // Record fields passed to calls while exactly one lock is held
  const MemRegion *OnlyLock = getOnlyHeldLock(State);
  if (!OnlyLock)
    return;

  // For each argument, if it's a field like obj->ptr, record its protecting lock
  for (unsigned I = 0, N = Call.getNumArgs(); I < N; ++I) {
    const Expr *AE = Call.getArgExpr(I);
    recordFieldUnderOnlyLock(AE, C);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad)
    return;

  // If exactly one lock is held and we are reading a field, record protection
  recordFieldUnderOnlyLockFromLoc(Loc, C);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Detect store of NULL to a protected field outside its protecting lock
  const MemRegion *LReg = Loc.getAsRegion();
  if (!LReg)
    return;

  const MemRegion *FR = getFieldRegionFromLoc(LReg);
  if (!FR)
    return;

  if (!isNullAssigned(S, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *FieldKey = FR->getBaseRegion();
  if (!FieldKey)
    return;

  const MemRegion *const *ProtLockPtr = State->get<ProtectedFieldToLock>(FieldKey);
  if (!ProtLockPtr)
    return; // We only warn for fields we have seen used under a lock
  const MemRegion *ProtLock = *ProtLockPtr;

  // Are we currently holding the protecting lock?
  if (State->contains<HeldLocks>(ProtLock))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Clearing pointer outside its protecting lock; may race with check-then-use", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects clearing shared pointers outside protecting spinlock (possible check-then-use race)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
