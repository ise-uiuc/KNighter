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
#include <optional>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program States ----------------
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousNoLockSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousAfterLockSet, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LockDepth, int)

namespace {

/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
      check::BranchCondition,
      check::PostCall,
      check::PreCall,
      check::Location,
      check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Invalid check then deref under lock", "Concurrency")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:

      // Helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;

      // Old helper kept for reference; superseded by analyzeNullCheckForInvalidBranch
      const MemRegion* extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const;

      bool thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const;
      bool hasEarlyExit(const Stmt *S, CheckerContext &C) const;

      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      // Extended: also return base expr for constraint/guard checks.
      bool stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                const ProgramStateRef &State,
                                const MemRegion *&TrackedPtrOut,
                                const Expr *&BaseExprOut) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;

      // New helpers to reduce false positives
      bool containsLoggingCall(const Stmt *S, CheckerContext &C) const;
      static bool isLoggingName(StringRef Name);

      // Analyze branch to find which side is "invalid" (null) for a pointer.
      enum class InvalidOnBranch { Then, Else, Unknown };
      struct NullCheckInfo {
        const MemRegion *PtrRegion = nullptr;
        InvalidOnBranch InvalidBranch = InvalidOnBranch::Unknown;
      };
      NullCheckInfo analyzeNullCheckForInvalidBranch(const Expr *Cond, CheckerContext &C) const;

      // New: Guard checks to suppress false positives.
      bool isGuardedByNonNullCheck(const Stmt *UseSite, const MemRegion *PtrR, CheckerContext &C) const;
      bool stmtIsInSubtree(const Stmt *Root, const Stmt *S) const;
      bool isKnownNonNullExpr(const Expr *E, CheckerContext &C) const;
};



// ---------------- Helper Implementations ----------------

static bool isNullLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

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

// Deprecated in logic; left to keep signature compatibility (not used by final logic).
const MemRegion* SAGenTestChecker::extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const {
  if (!Cond) return nullptr;
  const Expr *E = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LOr || Op == BO_LAnd) {
      if (const MemRegion *R = extractNullCheckedPointer(BO->getLHS(), C))
        return R;
      return extractNullCheckedPointer(BO->getRHS(), C);
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSNull = isNullLikeExpr(LHS, C);
      bool RHSNull = isNullLikeExpr(RHS, C);

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
    if (DRE->getType()->isAnyPointerType())
      return getBaseRegionFromExpr(DRE, C);
  }

  return nullptr;
}

// Determine if S contains any abrupt exit (return/goto/break/continue).
bool SAGenTestChecker::hasEarlyExit(const Stmt *S, CheckerContext &C) const {
  if (!S) return false;

  if (findSpecificTypeInChildren<ReturnStmt>(S)) return true;
  if (findSpecificTypeInChildren<GotoStmt>(S)) return true;
  if (findSpecificTypeInChildren<BreakStmt>(S)) return true;
  if (findSpecificTypeInChildren<ContinueStmt>(S)) return true;

  return false;
}

bool SAGenTestChecker::thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const {
  return hasEarlyExit(Then, C);
}

static bool stmtContainsCallWithName(const Stmt *S, StringRef Name, CheckerContext &C) {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getIdentifier()) {
        if (FD->getName().equals(Name))
          return true;
      }
    }
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
  std::string LowerStr = Name.lower();
  StringRef L(LowerStr);
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
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    static const char *LockNames[] = {
      "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
      "mutex_lock", "rt_mutex_lock", "raw_spin_lock",
      "xa_lock", "xa_lock_irq", "xa_lock_irqsave", "xa_lock_bh",
      "read_lock", "write_lock", "down_read", "down_write", "down"
    };
    for (const char *Name : LockNames)
      if (FnName.equals(Name))
        return true;
  }

  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

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
                                            const MemRegion *&TrackedPtrOut,
                                            const Expr *&BaseExprOut) const {
  TrackedPtrOut = nullptr;
  BaseExprOut = nullptr;
  if (!S) return false;

  // Look for "ptr->field"
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              BaseExprOut = DRE;
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
              BaseExprOut = DRE;
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
            BaseExprOut = DRE;
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

// Analyze the condition to find a null-check and determine which branch is "invalid".
SAGenTestChecker::NullCheckInfo
SAGenTestChecker::analyzeNullCheckForInvalidBranch(const Expr *Cond, CheckerContext &C) const {
  NullCheckInfo Info;
  if (!Cond) return Info;

  const Expr *E = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LOr || Op == BO_LAnd) {
      NullCheckInfo L = analyzeNullCheckForInvalidBranch(BO->getLHS(), C);
      if (L.PtrRegion && L.InvalidBranch == InvalidOnBranch::Then)
        return L;
      NullCheckInfo R = analyzeNullCheckForInvalidBranch(BO->getRHS(), C);
      if (R.PtrRegion && R.InvalidBranch == InvalidOnBranch::Then)
        return R;
      if (L.PtrRegion) return L;
      if (R.PtrRegion) return R;
      return Info;
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSNull = isNullLikeExpr(LHS, C);
      bool RHSNull = isNullLikeExpr(RHS, C);

      if (LHSNull && !RHSNull && RHS->getType()->isAnyPointerType() && isa<DeclRefExpr>(RHS)) {
        Info.PtrRegion = getBaseRegionFromExpr(RHS, C);
        Info.InvalidBranch = (Op == BO_EQ) ? InvalidOnBranch::Then : InvalidOnBranch::Else;
        return Info;
      }
      if (RHSNull && !LHSNull && LHS->getType()->isAnyPointerType() && isa<DeclRefExpr>(LHS)) {
        Info.PtrRegion = getBaseRegionFromExpr(LHS, C);
        Info.InvalidBranch = (Op == BO_EQ) ? InvalidOnBranch::Then : InvalidOnBranch::Else;
        return Info;
      }
      return Info;
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (Sub->getType()->isAnyPointerType() && isa<DeclRefExpr>(Sub)) {
        Info.PtrRegion = getBaseRegionFromExpr(Sub, C);
        Info.InvalidBranch = InvalidOnBranch::Then; // if (!ptr) => invalid on THEN
        return Info;
      }
      return Info;
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (DRE->getType()->isAnyPointerType()) {
      // if (ptr) => invalid on ELSE
      Info.PtrRegion = getBaseRegionFromExpr(DRE, C);
      Info.InvalidBranch = InvalidOnBranch::Else;
      return Info;
    }
  }

  return Info;
}

// Utility: check whether S is under the subtree Root.
bool SAGenTestChecker::stmtIsInSubtree(const Stmt *Root, const Stmt *S) const {
  if (!Root || !S) return false;
  if (Root == S) return true;
  for (const Stmt *Child : Root->children()) {
    if (stmtIsInSubtree(Child, S))
      return true;
  }
  return false;
}

// Suppress reports if the deref site is in a branch that guarantees PtrR != NULL.
bool SAGenTestChecker::isGuardedByNonNullCheck(const Stmt *UseSite, const MemRegion *PtrR, CheckerContext &C) const {
  if (!UseSite || !PtrR) return false;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(UseSite, C);
  if (!IS) return false;

  // Determine which branch contains UseSite.
  const Stmt *Then = IS->getThen();
  const Stmt *Else = IS->getElse();

  bool InThen = Then && stmtIsInSubtree(Then, UseSite);
  bool InElse = Else && stmtIsInSubtree(Else, UseSite);
  if (!InThen && !InElse)
    return false;

  NullCheckInfo NCI = analyzeNullCheckForInvalidBranch(IS->getCond(), C);
  if (!NCI.PtrRegion || NCI.InvalidBranch == InvalidOnBranch::Unknown)
    return false;

  if (NCI.PtrRegion != PtrR)
    return false;

  // If invalid is ELSE, then "if (ptr)" => non-null in THEN.
  if (NCI.InvalidBranch == InvalidOnBranch::Else && InThen)
    return true;

  // If invalid is THEN, then "if (!ptr)" => non-null in ELSE.
  if (NCI.InvalidBranch == InvalidOnBranch::Then && InElse)
    return true;

  return false;
}

// Path-sensitive: if state proves E != NULL, suppress.
bool SAGenTestChecker::isKnownNonNullExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(E, C.getLocationContext());
  SValBuilder &SB = C.getSValBuilder();

  SVal ZeroSV = SB.makeZeroVal(E->getType());

  std::optional<DefinedOrUnknownSVal> Cond;
  if (SV.getAs<Loc>()) {
    Loc LHS = SV.castAs<Loc>();
    if (!ZeroSV.getAs<Loc>())
      return false;
    Cond = SB.evalEQ(State, LHS, ZeroSV.castAs<Loc>());
  } else if (SV.getAs<NonLoc>()) {
    NonLoc LHS = SV.castAs<NonLoc>();
    if (!ZeroSV.getAs<NonLoc>())
      return false;
    Cond = SB.evalEQ(State, LHS, ZeroSV.castAs<NonLoc>());
  } else {
    return false;
  }

  if (!Cond)
    return false;

  auto Assumption = State->assume(*Cond);
  ProgramStateRef StEqNull = Assumption.first;
  ProgramStateRef StNeNull = Assumption.second;

  // If "SV == NULL" is infeasible and "SV != NULL" feasible -> known non-null.
  if (!StEqNull && StNeNull)
    return true;
  return false;
}

// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  NullCheckInfo NCI = analyzeNullCheckForInvalidBranch(Cond, C);
  if (!NCI.PtrRegion || NCI.InvalidBranch == InvalidOnBranch::Unknown)
    return;

  const Stmt *InvalidBranchStmt = (NCI.InvalidBranch == InvalidOnBranch::Then)
                                  ? IS->getThen()
                                  : IS->getElse();
  if (!InvalidBranchStmt)
    return; // No invalid branch to inspect (e.g., if (ptr) without else).

  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();

  // If inside the lock and we see re-validation with early-exit, clear suspicion.
  if (Depth > 0) {
    if (hasEarlyExit(InvalidBranchStmt, C)) {
      State = State->remove<SuspiciousAfterLockSet>(NCI.PtrRegion);
      C.addTransition(State);
    }
    return;
  }

  // Target pattern outside the lock: invalid branch must only log and not abort.
  if (!containsLoggingCall(InvalidBranchStmt, C))
    return;

  if (hasEarlyExit(InvalidBranchStmt, C))
    return;

  // Mark this pointer as suspicious: invalid-checked, no abort, and not under lock.
  State = State->add<SuspiciousNoLockSet>(NCI.PtrRegion);
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

    int NewDepth = State->get<LockDepth>();
    if (NewDepth <= 0) {
      auto After = State->get<SuspiciousAfterLockSet>();
      for (auto I = After.begin(), E = After.end(); I != E; ++I) {
        State = State->remove<SuspiciousAfterLockSet>(*I);
      }
      State = State->set<LockDepth>(0);
    }

    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

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
    if (!Found)
      continue;

    // Suppress if guarded by a non-null check or already known non-null.
    const Stmt *UseSite = Call.getOriginExpr();
    if (isGuardedByNonNullCheck(UseSite, MR, C) || isKnownNonNullExpr(ArgE, C)) {
      // Do not report, also clear to avoid future noisy reports.
      State = State->remove<SuspiciousAfterLockSet>(MR);
      C.addTransition(State);
      continue;
    }

    reportDerefBug(Call.getOriginExpr(), MR, C);
    State = State->remove<SuspiciousAfterLockSet>(MR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  const MemRegion *TrackedR = nullptr;
  const Expr *BaseExpr = nullptr;
  if (stmtDerefsTrackedPtr(S, C, State, TrackedR, BaseExpr) && TrackedR) {
    // Suppress if enclosed by a non-null guard or known non-null via constraints.
    if (isGuardedByNonNullCheck(S, TrackedR, C) || isKnownNonNullExpr(BaseExpr, C)) {
      State = State->remove<SuspiciousAfterLockSet>(TrackedR);
      C.addTransition(State);
      return;
    }

    reportDerefBug(S, TrackedR, C);
    State = State->remove<SuspiciousAfterLockSet>(TrackedR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->set<LockDepth>(0);
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
