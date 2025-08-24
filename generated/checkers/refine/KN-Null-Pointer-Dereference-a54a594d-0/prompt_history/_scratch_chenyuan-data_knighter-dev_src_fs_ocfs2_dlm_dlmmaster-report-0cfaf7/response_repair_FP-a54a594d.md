Refinement Plan:
- Root cause: The checker treats any pointer-appearance in a branch condition (e.g. if (ptr) or mixed conditions with &&/||) as a “null-check,” without tracking the polarity (invalid branch vs valid branch). It then looks for any logging within that branch subtree. This over-approximation marks pointers as “suspicious” even when the branch is the valid path (ptr != NULL), or when the pointer-check is embedded in a conjunction. This led to marking res as suspicious in ocfs2 code and reporting a false positive on a later dereference under a lock.
- Fixes:
  1. Precisely analyze the condition to determine which branch (then or else) corresponds to the “invalid” case for the pointer. Only that branch is inspected for “log-and-continue.”
  2. Support the disjunction form if (!ptr || ...) by treating the invalid branch as the then-branch when one of the disjuncts is a negative null-check. Reject conjunctions (&&) to avoid ambiguity and reduce FPs.
  3. Require the invalid branch to contain a logging call and to not contain an early exit or an aborting call (noreturn, BUG, panic, etc.).
  4. Inside a lock, if we observe a re-validation of the same pointer where the invalid branch exits (return/goto/BUG/noreturn), clear suspicion (as a sanitizer), using the same polarity-aware logic.
- Edge cases and regressions:
  - We only accept simple null checks: !ptr, ptr == NULL, NULL == ptr, ptr != NULL, and raw if (ptr). We intentionally avoid treating && as a valid null-check to prevent FPs.
  - We support || when one disjunct is a negative null-check (!ptr or ptr == NULL), mapping the invalid branch to then.
  - We add abort detection (noreturn/BUG/panic) to avoid flagging cases that really abort, preventing spurious reports.
- Maintain Clang-18 compatibility: Only use APIs available in Clang-18; keep all existing includes. Added helpers are internal; we preserve existing checker interface and registration.
- Detection of the original xhci bug: The pattern if (!ir || ir->intr_num == 0 || ir->intr_num >= ...) log; then lock; then ir->intr_num fits our logic precisely. The invalid branch is the then-branch (due to !ir in an ||), contains logging without early exit, and dereference occurs under lock.

Refined Code:
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

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program States ----------------
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousNoLockSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousAfterLockSet, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LockDepth, int)

namespace {

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
      enum class InvalidBranch { None, Then, Else };

      struct NullCheckInfo {
        const MemRegion *R = nullptr;
        InvalidBranch IB = InvalidBranch::None;
      };

      // Helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;

      NullCheckInfo analyzeNullCheck(const Expr *Cond, CheckerContext &C) const;
      bool branchHasEarlyExitOrAbort(const Stmt *Branch, CheckerContext &C) const;

      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      bool stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                const ProgramStateRef &State,
                                const MemRegion *&TrackedPtrOut) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;

      // New helpers to reduce false positives
      bool containsLoggingCall(const Stmt *S, CheckerContext &C) const;
      static bool isLoggingName(StringRef Name);
      static bool isAbortingName(StringRef Name);
      bool containsAbortingCall(const Stmt *S, CheckerContext &C) const;
};


// ---------------- Utility Functions (from prompt) ----------------

template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};

bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}

bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

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

SAGenTestChecker::NullCheckInfo
SAGenTestChecker::analyzeNullCheck(const Expr *Cond, CheckerContext &C) const {
  NullCheckInfo Info;

  if (!Cond) return Info;
  const Expr *E = Cond->IgnoreParenImpCasts();

  // Handle direct negation: if (!ptr) => invalid branch is 'then'
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (Sub && Sub->getType()->isAnyPointerType()) {
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
          Info.R = getBaseRegionFromExpr(DRE, C);
          Info.IB = InvalidBranch::Then;
          return Info;
        }
      }
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    // Avoid ambiguous conjunctions to reduce FPs.
    if (Op == BO_LAnd) {
      return Info; // do not match 'ptr && cond'
    }

    // For '||', if any disjunct is a negative null-check, then invalid branch is 'then'.
    if (Op == BO_LOr) {
      // Check LHS
      if (const auto *LHSUO = dyn_cast<UnaryOperator>(BO->getLHS()->IgnoreParenImpCasts())) {
        if (LHSUO->getOpcode() == UO_LNot) {
          const Expr *Sub = LHSUO->getSubExpr()->IgnoreParenImpCasts();
          if (Sub && Sub->getType()->isAnyPointerType()) {
            if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
              Info.R = getBaseRegionFromExpr(DRE, C);
              Info.IB = InvalidBranch::Then;
              return Info;
            }
          }
        }
      }
      if (const auto *LHSBO = dyn_cast<BinaryOperator>(BO->getLHS()->IgnoreParenImpCasts())) {
        BinaryOperator::Opcode LOp = LHSBO->getOpcode();
        if (LOp == BO_EQ) {
          const Expr *L = LHSBO->getLHS()->IgnoreParenImpCasts();
          const Expr *R = LHSBO->getRHS()->IgnoreParenImpCasts();
          if ((L && L->getType()->isAnyPointerType() && isNullLikeExpr(R, C) && isa<DeclRefExpr>(L)) ||
              (R && R->getType()->isAnyPointerType() && isNullLikeExpr(L, C) && isa<DeclRefExpr>(R))) {
            Info.R = getBaseRegionFromExpr((L->getType()->isAnyPointerType() ? L : R), C);
            Info.IB = InvalidBranch::Then;
            return Info;
          }
        }
      }
      // Check RHS similarly
      if (const auto *RHSUO = dyn_cast<UnaryOperator>(BO->getRHS()->IgnoreParenImpCasts())) {
        if (RHSUO->getOpcode() == UO_LNot) {
          const Expr *Sub = RHSUO->getSubExpr()->IgnoreParenImpCasts();
          if (Sub && Sub->getType()->isAnyPointerType()) {
            if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
              Info.R = getBaseRegionFromExpr(DRE, C);
              Info.IB = InvalidBranch::Then;
              return Info;
            }
          }
        }
      }
      if (const auto *RHSBO = dyn_cast<BinaryOperator>(BO->getRHS()->IgnoreParenImpCasts())) {
        BinaryOperator::Opcode ROp = RHSBO->getOpcode();
        if (ROp == BO_EQ) {
          const Expr *L = RHSBO->getLHS()->IgnoreParenImpCasts();
          const Expr *R = RHSBO->getRHS()->IgnoreParenImpCasts();
          if ((L && L->getType()->isAnyPointerType() && isNullLikeExpr(R, C) && isa<DeclRefExpr>(L)) ||
              (R && R->getType()->isAnyPointerType() && isNullLikeExpr(L, C) && isa<DeclRefExpr>(R))) {
            Info.R = getBaseRegionFromExpr((L->getType()->isAnyPointerType() ? L : R), C);
            Info.IB = InvalidBranch::Then;
            return Info;
          }
        }
      }
      return Info; // No pointer-null disjunct found: don't match
    }

    // Equality/inequality checks: ptr == NULL (invalid then), ptr != NULL (invalid else)
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSNull = isNullLikeExpr(LHS, C);
      bool RHSNull = isNullLikeExpr(RHS, C);

      if (LHSNull && RHS && RHS->getType()->isAnyPointerType() && isa<DeclRefExpr>(RHS)) {
        Info.R = getBaseRegionFromExpr(RHS, C);
        Info.IB = (Op == BO_EQ) ? InvalidBranch::Then : InvalidBranch::Else;
        return Info;
      } else if (RHSNull && LHS && LHS->getType()->isAnyPointerType() && isa<DeclRefExpr>(LHS)) {
        Info.R = getBaseRegionFromExpr(LHS, C);
        Info.IB = (Op == BO_EQ) ? InvalidBranch::Then : InvalidBranch::Else;
        return Info;
      }
    }
  }

  // Raw 'if (ptr)' => invalid is 'else'
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (DRE->getType()->isAnyPointerType()) {
      Info.R = getBaseRegionFromExpr(DRE, C);
      Info.IB = InvalidBranch::Else;
      return Info;
    }
  }

  return Info;
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
         Name.contains("WARN"); // uppercase macro
}

bool SAGenTestChecker::isAbortingName(StringRef Name) {
  // Coarse-grained kernel-ish abortors
  std::string LowerStr = Name.lower();
  StringRef L(LowerStr);
  return L.equals("bug") ||
         L.contains("bug_on") ||
         L.contains("panic") ||
         L.contains("assert") || // generic assert may abort
         L.contains("kassert") ||
         L.contains("unreachable");
}

bool SAGenTestChecker::containsLoggingCall(const Stmt *S, CheckerContext &C) const {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (const IdentifierInfo *ID = FD->getIdentifier()) {
        if (isLoggingName(ID->getName()))
          return true;
      }
      // Some logging functions might be macros resolving to builtins; fall through to text check
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

bool SAGenTestChecker::containsAbortingCall(const Stmt *S, CheckerContext &C) const {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD) {
        if (FD->isNoReturn())
          return true;
        if (FD->hasAttr<NoReturnAttr>())
          return true;
        if (const IdentifierInfo *ID = FD->getIdentifier()) {
          if (isAbortingName(ID->getName()))
            return true;
        }
      }
    }
    const Expr *CalleeE = CE->getCallee();
    if (CalleeE) {
      const SourceManager &SM = C.getSourceManager();
      const LangOptions &LangOpts = C.getLangOpts();
      CharSourceRange Range = CharSourceRange::getTokenRange(CalleeE->getSourceRange());
      StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
      if (isAbortingName(Text))
        return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsAbortingCall(Child, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::branchHasEarlyExitOrAbort(const Stmt *Branch, CheckerContext &C) const {
  if (!Branch) return false;

  if (findSpecificTypeInChildren<ReturnStmt>(Branch)) return true;
  if (findSpecificTypeInChildren<GotoStmt>(Branch)) return true;
  if (findSpecificTypeInChildren<BreakStmt>(Branch)) return true;
  if (findSpecificTypeInChildren<ContinueStmt>(Branch)) return true;

  if (containsAbortingCall(Branch, C)) return true;

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


// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  NullCheckInfo NCI = analyzeNullCheck(Cond, C);
  if (!NCI.R || NCI.IB == InvalidBranch::None)
    return;

  const Stmt *InvalidBranchStmt =
      (NCI.IB == InvalidBranch::Then) ? IS->getThen() : IS->getElse();
  if (!InvalidBranchStmt)
    return;

  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();

  // If inside the lock and we see re-validation where the invalid branch exits/aborts, clear suspicion.
  if (Depth > 0) {
    if (branchHasEarlyExitOrAbort(InvalidBranchStmt, C)) {
      State = State->remove<SuspiciousAfterLockSet>(NCI.R);
      C.addTransition(State);
    }
    return;
  }

  // Outside of lock: detect log-and-continue only on the invalid branch.
  if (!containsLoggingCall(InvalidBranchStmt, C))
    return;

  if (branchHasEarlyExitOrAbort(InvalidBranchStmt, C))
    return; // not "continue"; they do exit/abort

  // Mark this pointer as suspicious: invalid-checked, only logs, not under lock.
  State = State->add<SuspiciousNoLockSet>(NCI.R);
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

    auto After = State->get<SuspiciousAfterLockSet>();
    bool Found = false;
    for (auto I = After.begin(), E = After.end(); I != E; ++I) {
      if (*I == MR) { Found = true; break; }
    }

    if (Found) {
      reportDerefBug(Call.getOriginExpr(), MR, C);
      State = State->remove<SuspiciousAfterLockSet>(MR);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  const MemRegion *TrackedR = nullptr;
  if (stmtDerefsTrackedPtr(S, C, State, TrackedR) && TrackedR) {
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
```
