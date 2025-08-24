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
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallString.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track held locks by their ValueDecl (VarDecl for standalone lock vars,
// FieldDecl for struct-member locks).
REGISTER_SET_WITH_PROGRAMSTATE(HeldLockKeys, const ValueDecl*)

namespace {
class SAGenTestChecker
  : public Checker<
      check::PreCall,
      check::BranchCondition,
      check::Location,
      check::Bind> {
  mutable std::unique_ptr<BugType> BT;

  // Cross-function map: for each pointer FieldDecl, remember which locks
  // (by ValueDecl) we observed being held when the field was used/checked.
  mutable llvm::DenseMap<const FieldDecl*, llvm::SmallPtrSet<const ValueDecl*, 2>> FieldProtectingLocks;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
            "Lock-protected pointer cleared without holding lock",
            "Concurrency")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper functions
  static const ValueDecl *extractLockKeyFromExpr(const Expr *E);
  static const MemberExpr *findPointerMemberInExpr(const Expr *E);
  static const MemberExpr *findPointerMemberInStmtPreferLHS(const Stmt *S);
  static bool isZeroSVal(SVal V);

  static bool isLockAcquire(const CallEvent &Call, CheckerContext &C);
  static bool isLockRelease(const CallEvent &Call, CheckerContext &C);

  void recordProtectedFieldUnderHeldLocks(const MemberExpr *ME, ProgramStateRef State) const;
  bool holdsAnyProtectingLockForField(const FieldDecl *FD, ProgramStateRef State) const;

  void reportUnlockClear(const Stmt *S, CheckerContext &C,
                         const FieldDecl *FD,
                         const ValueDecl *OneLockVD) const;
};

// -------------------- Helper Implementations --------------------

static const ValueDecl *extractDeclFromBaseExpr(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<ValueDecl>(DRE->getDecl());
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    return dyn_cast<ValueDecl>(ME->getMemberDecl());
  }
  return nullptr;
}

const ValueDecl *SAGenTestChecker::extractLockKeyFromExpr(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();

  // Handle &expr
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_AddrOf) {
      return extractDeclFromBaseExpr(UO->getSubExpr());
    }
  }

  // Direct DeclRefExpr or MemberExpr
  return extractDeclFromBaseExpr(E);
}

const MemberExpr *SAGenTestChecker::findPointerMemberInExpr(const Expr *E) {
  if (!E) return nullptr;
  // Try direct member first
  if (const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenImpCasts())) {
    if (ME->getType()->isPointerType())
      return ME;
  }

  // Search children for any MemberExpr
  if (const auto *Found = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (Found->getType()->isPointerType())
      return Found;
  }
  return nullptr;
}

const MemberExpr *SAGenTestChecker::findPointerMemberInStmtPreferLHS(const Stmt *S) {
  if (!S) return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS();
      if (const auto *ME = findPointerMemberInExpr(LHS))
        return ME;
    }
  }
  // Fallback: any MemberExpr in S
  if (const auto *Found = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (Found->getType()->isPointerType())
      return Found;
  }
  return nullptr;
}

bool SAGenTestChecker::isZeroSVal(SVal V) {
  return V.isZeroConstant();
}

static bool CallNameIs(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;
  return ExprHasName(OE, Name, C);
}

bool SAGenTestChecker::isLockAcquire(const CallEvent &Call, CheckerContext &C) {
  return CallNameIs(Call, C, "spin_lock") ||
         CallNameIs(Call, C, "spin_lock_irqsave") ||
         CallNameIs(Call, C, "raw_spin_lock") ||
         CallNameIs(Call, C, "raw_spin_lock_irqsave");
}

bool SAGenTestChecker::isLockRelease(const CallEvent &Call, CheckerContext &C) {
  return CallNameIs(Call, C, "spin_unlock") ||
         CallNameIs(Call, C, "spin_unlock_irqrestore") ||
         CallNameIs(Call, C, "raw_spin_unlock") ||
         CallNameIs(Call, C, "raw_spin_unlock_irqrestore");
}

void SAGenTestChecker::recordProtectedFieldUnderHeldLocks(const MemberExpr *ME,
                                                          ProgramStateRef State) const {
  if (!ME) return;
  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD) return;
  if (!ME->getType()->isPointerType()) return;

  auto LockSet = State->get<HeldLockKeys>();
  if (LockSet.isEmpty()) return;

  auto &LockBucket = FieldProtectingLocks[FD]; // creates if absent
  for (auto I = LockSet.begin(); I != LockSet.end(); ++I) {
    if (*I)
      LockBucket.insert(*I);
  }
}

bool SAGenTestChecker::holdsAnyProtectingLockForField(const FieldDecl *FD,
                                                      ProgramStateRef State) const {
  auto It = FieldProtectingLocks.find(FD);
  if (It == FieldProtectingLocks.end())
    return false; // No known protecting locks recorded.

  const auto &Protecting = It->second;

  auto LockSet = State->get<HeldLockKeys>();
  if (LockSet.isEmpty())
    return false;

  for (auto I = LockSet.begin(); I != LockSet.end(); ++I) {
    if (Protecting.count(*I))
      return true;
  }
  return false;
}

void SAGenTestChecker::reportUnlockClear(const Stmt *S, CheckerContext &C,
                                         const FieldDecl *FD,
                                         const ValueDecl *OneLockVD) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  llvm::SmallString<128> Msg;
  Msg += "Clearing a lock-protected pointer without holding its lock";
  if (OneLockVD && OneLockVD->getIdentifier()) {
    Msg += " ('";
    Msg += OneLockVD->getName();
    Msg += "')";
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);
  if (S)
    R->addRange(S->getSourceRange());
  if (FD)
    R->addNote("Field is used under lock elsewhere",
               PathDiagnosticLocation::createBegin(FD, C.getSourceManager()));
  C.emitReport(std::move(R));
}

// -------------------- Checker Callbacks --------------------

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Handle lock acquisition
  if (isLockAcquire(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      if (const Expr *Arg0 = Call.getArgExpr(0)) {
        if (const ValueDecl *LockVD = extractLockKeyFromExpr(Arg0)) {
          State = State->add<HeldLockKeys>(LockVD);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // Handle lock release
  if (isLockRelease(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      if (const Expr *Arg0 = Call.getArgExpr(0)) {
        if (const ValueDecl *LockVD = extractLockKeyFromExpr(Arg0)) {
          State = State->remove<HeldLockKeys>(LockVD);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // For other calls, if we currently hold locks, record pointer-field args
  auto LockSet = State->get<HeldLockKeys>();
  if (!LockSet.isEmpty()) {
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      const Expr *Arg = Call.getArgExpr(i);
      if (!Arg) continue;
      if (const auto *ME = findPointerMemberInExpr(Arg)) {
        recordProtectedFieldUnderHeldLocks(ME, State);
      }
    }
  }
  // Even if we didn't change State, adding a transition is not necessary.
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition) {
    C.addTransition(State);
    return;
  }

  // Record pointer-field checks under lock.
  auto LockSet = State->get<HeldLockKeys>();
  if (!LockSet.isEmpty()) {
    if (const auto *CondE = dyn_cast<Expr>(Condition)) {
      if (const auto *ME = findPointerMemberInExpr(CondE)) {
        recordProtectedFieldUnderHeldLocks(ME, State);
      }
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad || !S) return;

  ProgramStateRef State = C.getState();
  auto LockSet = State->get<HeldLockKeys>();
  if (LockSet.isEmpty()) return;

  // Attempt to record loads of pointer fields under lock as "protected".
  if (const auto *ME = findPointerMemberInStmtPreferLHS(S)) {
    recordProtectedFieldUnderHeldLocks(ME, State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S) return;

  // We are interested in writes like: some_struct->ptr_field = NULL;
  if (!isZeroSVal(Val))
    return;

  const MemberExpr *ME = findPointerMemberInStmtPreferLHS(S);
  if (!ME) return;

  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD) return;

  if (!ME->getType()->isPointerType())
    return;

  // If this field has never been observed as lock-protected elsewhere, skip.
  auto It = FieldProtectingLocks.find(FD);
  if (It == FieldProtectingLocks.end() || It->second.empty())
    return;

  ProgramStateRef State = C.getState();
  // If currently not holding any of its protecting locks, report.
  if (!holdsAnyProtectingLockForField(FD, State)) {
    // Pick one lock to mention if available
    const ValueDecl *MentionVD = nullptr;
    if (!It->second.empty())
      MentionVD = *It->second.begin();
    reportUnlockClear(S, C, FD, MentionVD);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects clearing of lock-protected pointer fields outside their protecting lock",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
