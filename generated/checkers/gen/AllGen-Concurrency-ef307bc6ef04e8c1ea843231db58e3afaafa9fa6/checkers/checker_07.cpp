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

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(LockCountMap, const MemRegion*, unsigned)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LastUnlockedLock, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::BeginFunction,
    check::EndFunction,
    check::PreCall,
    check::PostCall,
    check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unlock-before-nullify of shared pointer", "Concurrency")) {}

      void checkBeginFunction(CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      bool isLockFunc(const CallEvent &Call, CheckerContext &C) const;
      bool isUnlockFunc(const CallEvent &Call, CheckerContext &C) const;
      const MemRegion *getLockRegionFromCall(const CallEvent &Call, CheckerContext &C) const;
      bool isNullRHS(SVal Val, const Expr *RHS, CheckerContext &C) const;
};

bool SAGenTestChecker::isLockFunc(const CallEvent &Call, CheckerContext &C) const {
  static const char *LockNames[] = {
    "spin_lock", "spin_lock_irq", "spin_lock_bh", "spin_lock_irqsave",
    "mutex_lock", "read_lock", "write_lock"
  };
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  for (const char *N : LockNames) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isUnlockFunc(const CallEvent &Call, CheckerContext &C) const {
  static const char *UnlockNames[] = {
    "spin_unlock", "spin_unlock_irq", "spin_unlock_bh", "spin_unlock_irqrestore",
    "mutex_unlock", "read_unlock", "write_unlock"
  };
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  for (const char *N : UnlockNames) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getLockRegionFromCall(const CallEvent &Call, CheckerContext &C) const {
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

bool SAGenTestChecker::isNullRHS(SVal V, const Expr *RHS, CheckerContext &C) const {
  if (auto DV = V.getAs<DefinedOrUnknownSVal>()) {
    if (DV->isZeroConstant())
      return true;
  }

  if (const Expr *RE = dyn_cast_or_null<Expr>(RHS)) {
    // Use AST check for null pointer constants
    if (RE->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNull))
      return true;

    // Fallback: evaluate as int
    llvm::APSInt Res;
    if (EvaluateExprToInt(Res, RE, C)) {
      if (Res == 0)
        return true;
    }

    // Fallback to textual check for NULL
    if (ExprHasName(RE, "NULL", C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->set<LastUnlockedLock>(nullptr);
  C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->set<LastUnlockedLock>(nullptr);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isLockFunc(Call, C)) {
    const MemRegion *LR = getLockRegionFromCall(Call, C);
    if (LR) {
      const unsigned *Cnt = State->get<LockCountMap>(LR);
      unsigned NewCnt = (Cnt ? *Cnt : 0) + 1;
      State = State->set<LockCountMap>(LR, NewCnt);
    }
    // Once we acquire a lock, clear the "just-unlocked" marker.
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  // For any non-lock/non-unlock call, shrink the "just-unlocked" window.
  if (!isUnlockFunc(Call, C)) {
    const MemRegion *LUL = State->get<LastUnlockedLock>();
    if (LUL) {
      State = State->set<LastUnlockedLock>(nullptr);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isUnlockFunc(Call, C)) {
    const MemRegion *LR = getLockRegionFromCall(Call, C);
    if (LR) {
      const unsigned *Cnt = State->get<LockCountMap>(LR);
      if (Cnt && *Cnt > 1) {
        State = State->set<LockCountMap>(LR, *Cnt - 1);
      } else {
        State = State->remove<LockCountMap>(LR);
      }
      // Mark this lock as just unlocked
      State = State->set<LastUnlockedLock>(LR);
    } else {
      // Defensive
      State = State->set<LastUnlockedLock>(nullptr);
    }
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *JustUnlocked = State->get<LastUnlockedLock>();
  if (!JustUnlocked)
    return;

  // Ensure the lock is not currently held.
  if (const unsigned *Cnt = State->get<LockCountMap>(JustUnlocked)) {
    if (*Cnt > 0) {
      // Clear the window and stop.
      State = State->set<LastUnlockedLock>(nullptr);
      C.addTransition(State);
      return;
    }
  }

  // We only care about assignments, particularly to struct->pointer fields.
  const BinaryOperator *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp()) {
    // Clear window after the first subsequent bind to keep "immediate" semantics.
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS) {
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  LHS = LHS->IgnoreParenCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(LHS);
  if (!ME || !ME->isArrow()) {
    // Not a pointer member access via '->'
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast<FieldDecl>(VD);
  if (!FD) {
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  QualType FT = FD->getType();
  if (!FT.getTypePtr() || !FT->isPointerType()) {
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  // Check RHS is NULL
  if (!isNullRHS(Val, RHS, C)) {
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  // All conditions met: just-unlocked, assignment to pointer field, set to NULL.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) {
    State = State->set<LastUnlockedLock>(nullptr);
    C.addTransition(State);
    return;
  }

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Setting shared pointer field to NULL right after unlocking; move the assignment before unlock", N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));

  // Clear the window to avoid duplicates.
  State = State->set<LastUnlockedLock>(nullptr);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect unlock-before-nullify of shared pointer fields (TOCTOU race)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
