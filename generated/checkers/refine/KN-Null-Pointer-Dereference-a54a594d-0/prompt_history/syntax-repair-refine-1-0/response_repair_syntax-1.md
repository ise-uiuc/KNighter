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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include <string>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program States ----------------
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousNoLockSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousAfterLockSet, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LockDepth, int)

// Keep a small set of "index variables" that are assigned from a suspicious
// pointer's field after lock acquisition. This adds precision for the
// array[idx]-under-lock part of the pattern when present, while remaining optional.
REGISTER_SET_WITH_PROGRAMSTATE(IndexVarsSet, const MemRegion*)

namespace {

/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
      check::BranchCondition,
      check::PostCall,
      check::PreCall,
      check::Location,
      check::EndFunction,
      check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Invalid check then deref under lock", "Concurrency")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;

      const MemRegion* extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const;
      bool thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const;

      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      bool stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                const ProgramStateRef &State,
                                const MemRegion *&TrackedPtrOut) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;

      // New helpers to reduce false positives
      bool containsLoggingCall(const Stmt *S, CheckerContext &C) const;
      static bool isLoggingName(StringRef Name);

      // New FP suppression gates
      bool pointerMayBeNullNow(const MemRegion *PtrVarRegion, CheckerContext &C) const;
      bool isAllocatorLikeFunction(CheckerContext &C) const;
      bool isFalsePositive(const Stmt *UseSite, const MemRegion *PtrVarRegion, CheckerContext &C) const;

      // Lightweight pattern aid: track array index var assigned from ptr->field after lock
      bool isIndexVarFromTrackedPtr(const Expr *IdxE, ProgramStateRef State, CheckerContext &C) const;
};



// ---------------- Helper Implementations ----------------

static bool isNullLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  // Check for null pointer constant per AST utilities
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

  // Also try constant-evaluated integer 0
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C)) {
    if (Val == 0)
      return true;
  }
  return false;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const {
  if (!Cond) return nullptr;
  const Expr *E = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LOr || Op == BO_LAnd) {
      // Recurse into both sides, prefer LHS first
      if (const MemRegion *R = extractNullCheckedPointer(BO->getLHS(), C))
        return R;
      return extractNullCheckedPointer(BO->getRHS(), C);
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSNull = isNullLikeExpr(LHS, C);
      bool RHSNull = isNullLikeExpr(RHS, C);

      // Look for (ptr == NULL) or (ptr != NULL)
      if (LHSNull && !RHSNull) {
        if (RHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(RHS))
            return getBaseRegionFromExpr(RHS, C);
        }
      } else if (RHSNull && !LHSNull) {
        if (LHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(LHS))
            return getBaseRegionFromExpr(LHS, C);
        }
      }
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (Sub->getType()->isAnyPointerType() && isa<DeclRefExpr>(Sub)) {
        return getBaseRegionFromExpr(Sub, C);
      }
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    // In conditions like "if (ptr)" treat it as a null-check too.
    if (DRE->getType()->isAnyPointerType())
      return getBaseRegionFromExpr(DRE, C);
  }

  return nullptr;
}

bool SAGenTestChecker::thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const {
  if (!Then) return false;

  if (findSpecificTypeInChildren<ReturnStmt>(Then)) return true;
  if (findSpecificTypeInChildren<GotoStmt>(Then)) return true;
  if (findSpecificTypeInChildren<BreakStmt>(Then)) return true;
  if (findSpecificTypeInChildren<ContinueStmt>(Then)) return true;

  return false;
}

static bool stmtContainsCallWithName(const Stmt *S, StringRef Name, CheckerContext &C) {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    // Try callee identifier first
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getIdentifier()) {
        if (FD->getName().equals(Name))
          return true;
      }
    }
    // Fallback to source text name matching (macro-expanded cases)
    if (ExprHasName(CE->getCallee(), Name, C))
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (stmtContainsCallWithName(Child, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLoggingName(StringRef Name) {
  // Normalize to lowercase for case-insensitive matching.
  std::string Lower = Name.lower();
  StringRef L(Lower);
  return L.contains("dbg") ||
         L.contains("warn") ||
         L.contains("err") ||
         L.contains("printk") ||
         L.startswith("pr_") ||
         L.contains("log") ||
         L.startswith("dev_") ||
         L.equals("xhci_dbg") ||
         Name.contains("WARN");
}

bool SAGenTestChecker::containsLoggingCall(const Stmt *S, CheckerContext &C) const {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (const IdentifierInfo *ID = FD->getIdentifier()) {
        if (isLoggingName(ID->getName()))
          return true;
      }
    }
    // Fallback to textual sniffing on callee/source if no identifier
    const Expr *CalleeE = CE->getCallee();
    if (CalleeE) {
      const SourceManager &SM = C.getSourceManager();
      const LangOptions &LangOpts = C.getLangOpts();
      CharSourceRange Range = CharSourceRange::getTokenRange(CalleeE->getSourceRange());
      StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
      if (isLoggingName(Text))
        return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsLoggingCall(Child, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockAcquire(const CallEvent &Call, CheckerContext &C) const {
  // Prefer callee identifier when available
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    // Common Linux locking APIs
    static const char *LockNames[] = {
      "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
      "mutex_lock", "rt_mutex_lock", "raw_spin_lock",
      // XA/RCU-like helpers used as locks in some subsystems
      "xa_lock", "xa_lock_irq", "xa_lock_irqsave", "xa_lock_bh",
      "read_lock", "write_lock", "down_read", "down_write", "down"
    };
    for (const char *Name : LockNames)
      if (FnName.equals(Name))
        return true;
  }

  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // Fallback textual match when identifier is not available or macro-expanded
  static const char *LockTextNames[] = {
    "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
    "mutex_lock", "rt_mutex_lock", "raw_spin_lock",
    "xa_lock", "xa_lock_irq", "xa_lock_irqsave", "xa_lock_bh",
    "read_lock", "write_lock", "down_read", "down_write", "down("
  };

  for (const char *Name : LockTextNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockRelease(const CallEvent &Call, CheckerContext &C) const {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    static const char *UnlockNames[] = {
      "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
      "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock",
      "xa_unlock", "xa_unlock_irq", "xa_unlock_irqrestore", "xa_unlock_bh",
      "read_unlock", "write_unlock", "up_read", "up_write", "up"
    };
    for (const char *Name : UnlockNames)
      if (FnName.equals(Name))
        return true;
  }

  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  static const char *UnlockTextNames[] = {
    "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
    "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock",
    "xa_unlock", "xa_unlock_irq", "xa_unlock_irqrestore", "xa_unlock_bh",
    "read_unlock", "write_unlock", "up_read", "up_write", "up("
  };

  for (const char *Name : UnlockTextNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                            const ProgramStateRef &State,
                                            const MemRegion *&TrackedPtrOut) const {
  TrackedPtrOut = nullptr;
  if (!S) return false;

  // Look for "ptr->field"
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Base->IgnoreParenImpCasts())) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "*ptr"
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "ptr[idx]"
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
      if (MR) {
        auto Set = State->get<SuspiciousAfterLockSet>();
        for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
          if (*I == MR) {
            TrackedPtrOut = MR;
            return true;
          }
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Invalid-checked pointer is logged but not aborted; later dereferenced under lock", N);
  if (S)
    Report->addRange(S->getSourceRange());
  Report->markInteresting(R);
  C.emitReport(std::move(Report));
}

bool SAGenTestChecker::pointerMayBeNullNow(const MemRegion *PtrVarRegion, CheckerContext &C) const {
  if (!PtrVarRegion) return true;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();

  // Read the current value of the pointer variable.
  loc::MemRegionVal L(PtrVarRegion);
  SVal V = State->getSVal(L);

  if (V.isUnknownOrUndef())
    return true; // be conservative

  // Build (V == NULL)
  SVal NullV = SVB.makeZeroVal(C.getASTContext().VoidPtrTy);
  SVal Eq = SVB.evalEQ(State, V, NullV);
  if (Eq.isUnknownOrUndef())
    return true;

  if (auto EqNL = Eq.getAs<NonLoc>()) {
    ProgramStateRef StIsNull = State->assume(*EqNL, true);
    return (bool)StIsNull; // feasible to be null?
  }

  // If it's a Loc comparison and not a NonLoc, be conservative.
  return true;
}

bool SAGenTestChecker::isAllocatorLikeFunction(CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  if (!LC) return false;
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (!FD || !FD->getIdentifier()) return false;
  StringRef Name = FD->getName();

  // Heuristic: allocator/initializer-like routines frequently use defensive checks.
  // Keep this small and conservative to avoid suppressing real issues elsewhere.
  std::string Lower = Name.lower();
  StringRef L(Lower);
  if (L.contains("alloc") ||
      L.contains("create") ||
      L.contains("setup") ||
      L.contains("register") ||
      L.contains("init"))
    return true;

  return false;
}

bool SAGenTestChecker::isFalsePositive(const Stmt *UseSite, const MemRegion *PtrVarRegion, CheckerContext &C) const {
  // Gate 1: current path must allow ptr == NULL to be feasible.
  if (!pointerMayBeNullNow(PtrVarRegion, C))
    return true; // Definitely non-null along this path => FP for our pattern.

  // Gate 2: optionally suppress allocator/initializer-like functions.
  if (isAllocatorLikeFunction(C))
    return true;

  (void)UseSite;
  return false;
}

bool SAGenTestChecker::isIndexVarFromTrackedPtr(const Expr *IdxE, ProgramStateRef State, CheckerContext &C) const {
  if (!IdxE) return false;
  IdxE = IdxE->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(IdxE)) {
    const MemRegion *VR = getBaseRegionFromExpr(DRE, C);
    if (!VR) return false;
    auto Set = State->get<IndexVarsSet>();
    for (auto I = Set.begin(), E = Set.end(); I != E; ++I)
      if (*I == VR)
        return true;
  }
  return false;
}


// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Find the containing IfStmt
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  const Stmt *Then = IS->getThen();
  // Identify the pointer that is being null-checked in the condition
  const MemRegion *R = extractNullCheckedPointer(Cond, C);
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();

  // If inside the lock and we see re-validation with early-exit, clear suspicion.
  if (Depth > 0) {
    if (thenHasEarlyExit(Then, C)) {
      State = State->remove<SuspiciousAfterLockSet>(R);
      C.addTransition(State);
    }
    return;
  }

  // We only care about the "log-and-continue" pattern outside the lock:
  // - Then branch must not have early exit
  // - Then branch must contain a logging call (dbg/warn/err/printk/...)
  if (thenHasEarlyExit(Then, C))
    return;

  if (!containsLoggingCall(Then, C))
    return; // Avoid FPs where the check is not "log-only".

  // Suppress noisy patterns in allocator/initializer-like functions.
  if (isAllocatorLikeFunction(C))
    return;

  // Mark this pointer as suspicious: invalid-checked, no abort, and not under lock.
  State = State->add<SuspiciousNoLockSet>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isLockAcquire(Call, C)) {
    int Depth = State->get<LockDepth>();
    State = State->set<LockDepth>(Depth + 1);

    // Move all regions from SuspiciousNoLockSet to SuspiciousAfterLockSet
    auto NoLock = State->get<SuspiciousNoLockSet>();
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      const MemRegion *R = *I;
      State = State->add<SuspiciousAfterLockSet>(R);
    }
    // Clear SuspiciousNoLockSet after transferring
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      State = State->remove<SuspiciousNoLockSet>(*I);
    }

    C.addTransition(State);
    return;
  }

  if (isLockRelease(Call, C)) {
    int Depth = State->get<LockDepth>();
    if (Depth > 0)
      State = State->set<LockDepth>(Depth - 1);
    else
      State = State->set<LockDepth>(0);

    // When fully unlocked, clear AfterLockSet and index-vars to avoid stale carry-over.
    int NewDepth = State->get<LockDepth>();
    if (NewDepth <= 0) {
      auto After = State->get<SuspiciousAfterLockSet>();
      for (auto I = After.begin(), E = After.end(); I != E; ++I) {
        State = State->remove<SuspiciousAfterLockSet>(*I);
      }
      auto IdxVars = State->get<IndexVarsSet>();
      for (auto I = IdxVars.begin(), E = IdxVars.end(); I != E; ++I) {
        State = State->remove<IndexVarsSet>(*I);
      }
      State = State->set<LockDepth>(0);
    }

    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Only report deref if we're currently under a lock.
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  // For calls that are known to dereference pointer arguments, check if any of those
  // arguments correspond to our suspicious pointer after the lock.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Is this pointer in the "after-lock" suspicious set?
    auto After = State->get<SuspiciousAfterLockSet>();
    bool Found = false;
    for (auto I = After.begin(), E = After.end(); I != E; ++I) {
      if (*I == MR) { Found = true; break; }
    }

    if (Found) {
      // FP suppression gates: only report if ptr may be null now and not in allocator-like routine.
      if (!isFalsePositive(Call.getOriginExpr(), MR, C)) {
        reportDerefBug(Call.getOriginExpr(), MR, C);
      }
      // Remove to avoid duplicate reports.
      State = State->remove<SuspiciousAfterLockSet>(MR);
      C.addTransition(State);
      // do not return early; check other params as well
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  // Heuristic: for members like ir->intr_num or deref *ir or arr like ir[idx],
  // extract the base DeclRefExpr and see if it matches our tracked pointer.
  const MemRegion *TrackedR = nullptr;
  if (stmtDerefsTrackedPtr(S, C, State, TrackedR) && TrackedR) {
    if (!isFalsePositive(S, TrackedR, C)) {
      reportDerefBug(S, TrackedR, C);
    }
    State = State->remove<SuspiciousAfterLockSet>(TrackedR);
    C.addTransition(State);
    return;
  }

  // Optional precision boost: if we see array subscript with an index variable
  // that was assigned from ptr->field after lock, this is a characteristic
  // part of the target pattern; we can treat it as a corroborating use-site.
  if (const auto *ASE = dyn_cast_or_null<ArraySubscriptExpr>(S)) {
    if (isIndexVarFromTrackedPtr(ASE->getIdx(), State, C)) {
      // Report against any tracked pointer; this is a heuristic for matching
      // the "use array[idx]" part. Keep FP gates.
      auto After = State->get<SuspiciousAfterLockSet>();
      for (auto I = After.begin(), E = After.end(); I != E; ++I) {
        const MemRegion *R = *I;
        if (!isFalsePositive(S, R, C)) {
          reportDerefBug(S, R, C);
        }
        State = State->remove<SuspiciousAfterLockSet>(R);
      }
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Record index variables assigned from ptr->field inside the lock to
  // improve recognition of the array[idx] pattern.
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  // LHS must be a variable region.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) return;

  // RHS should be a MemberExpr with arrow on a tracked pointer.
  if (!S) return;
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (!BO->isAssignmentOp())
      return;

    const Expr *RHS = BO->getRHS();
    const auto *ME = dyn_cast_or_null<MemberExpr>(RHS ? RHS->IgnoreParenImpCasts() : nullptr);
    if (!ME || !ME->isArrow())
      return;

    const Expr *Base = ME->getBase();
    if (!Base) return;
    const MemRegion *BaseR = getBaseRegionFromExpr(Base, C);
    if (!BaseR) return;

    auto After = State->get<SuspiciousAfterLockSet>();
    bool Found = false;
    for (auto I = After.begin(), E = After.end(); I != E; ++I) {
      if (*I == BaseR) { Found = true; break; }
    }
    if (!Found) return;

    // Record this LHS variable region as an "index var" derived from the suspicious pointer.
    State = State->add<IndexVarsSet>(LHSReg->getBaseRegion());
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Best-effort cleanup of lock depth; sets will be discarded with state anyway.
  ProgramStateRef State = C.getState();
  State = State->set<LockDepth>(0);

  // Cleanup helper sets too.
  auto After = State->get<SuspiciousAfterLockSet>();
  for (auto I = After.begin(), E = After.end(); I != E; ++I) {
    State = State->remove<SuspiciousAfterLockSet>(*I);
  }
  auto IdxVars = State->get<IndexVarsSet>();
  for (auto I = IdxVars.begin(), E = IdxVars.end(); I != E; ++I) {
    State = State->remove<IndexVarsSet>(*I);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects null-check that only logs without abort, then dereferences under lock",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
