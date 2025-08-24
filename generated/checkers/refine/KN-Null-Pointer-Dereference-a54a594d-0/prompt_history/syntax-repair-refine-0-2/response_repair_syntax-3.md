```cpp
#include <memory>
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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "clang/AST/ParentMapContext.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program States ----------------
// Map pointer region -> stack frame where it was (invalid-)checked outside the lock.
REGISTER_MAP_WITH_PROGRAMSTATE(SuspiciousNoLockMap, const MemRegion*, const StackFrameContext*)
// Map pointer region -> stack frame where the lock was later acquired.
REGISTER_MAP_WITH_PROGRAMSTATE(SuspiciousAfterLockMap, const MemRegion*, const StackFrameContext*)
// Track lock depth per stack frame to avoid cross-frame contamination.
REGISTER_MAP_WITH_PROGRAMSTATE(FrameLockDepthMap, const StackFrameContext*, unsigned)

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
      SAGenTestChecker() = default;

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:
      // Lock helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;
      unsigned getFrameLockDepth(ProgramStateRef State, const StackFrameContext *SFC) const;
      ProgramStateRef setFrameLockDepth(ProgramStateRef State, const StackFrameContext *SFC, unsigned Depth) const;

      // Null-check extraction and validation helpers
      const MemRegion* extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const;
      bool thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const;
      bool containsLoggingCall(const Stmt *S, CheckerContext &C) const;
      bool thenWritesToVar(const Stmt *Then, const MemRegion *R, CheckerContext &C) const;

      // Region helpers
      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      // Deref detection
      bool stmtDerefsAnyPtr(const Stmt *S, CheckerContext &C, const MemRegion *&PtrOut) const;

      // False positive helper
      bool isFalsePositive(const Stmt *Then, const MemRegion *R, CheckerContext &C) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;
};


// ---------------- Utility Helpers ----------------

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

// This helper is currently unused. Provide a stub that compiles across API versions.
const llvm::APSInt *inferSymbolMaxVal(SymbolRef /*Sym*/, CheckerContext &/*C*/) {
  return nullptr;
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

// Example known-deref table (user-provided externally)
extern llvm::SmallVector<KnownDerefFunction, 4> DerefTable;

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
  const LangOptions &LangOpts = C.getASTContext().getLangOpts();
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

bool SAGenTestChecker::thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const {
  if (!Then) return false;

  if (findSpecificTypeInChildren<ReturnStmt>(Then)) return true;
  if (findSpecificTypeInChildren<GotoStmt>(Then)) return true;
  if (findSpecificTypeInChildren<BreakStmt>(Then)) return true;
  if (findSpecificTypeInChildren<ContinueStmt>(Then)) return true;

  return false;
}

bool SAGenTestChecker::containsLoggingCall(const Stmt *S, CheckerContext &C) const {
  if (!S) return false;

  // Names commonly used for logging in the kernel and drivers.
  static const char *LogNames[] = {
    "printk", "pr_err", "pr_warn", "pr_info", "pr_notice", "pr_debug",
    "dev_err", "dev_warn", "dev_info", "dev_dbg",
    "xhci_dbg", "WARN", "WARN_ON", "pr_warn_once", "dev_warn_once"
  };

  // DFS over statements
  llvm::SmallVector<const Stmt*, 16> Worklist;
  Worklist.push_back(S);
  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (!Cur) continue;

    if (const auto *CE = dyn_cast<CallExpr>(Cur)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        StringRef Name = FD->getName();
        for (const char *Ln : LogNames) {
          if (Name.equals(Ln))
            return true;
        }
      } else {
        // Fallback: textual match for macros that might not have a direct callee
        for (const char *Ln : LogNames) {
          if (ExprHasName(CE, Ln, C))
            return true;
          }
      }
    }

    for (const Stmt *Child : Cur->children())
      if (Child) Worklist.push_back(Child);
  }

  return false;
}

bool SAGenTestChecker::thenWritesToVar(const Stmt *Then, const MemRegion *R, CheckerContext &C) const {
  if (!Then || !R) return false;

  llvm::SmallVector<const Stmt*, 16> Worklist;
  Worklist.push_back(Then);
  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (!Cur) continue;

    if (const auto *BO = dyn_cast<BinaryOperator>(Cur)) {
      if (BO->getOpcode() == BO_Assign) {
        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          const MemRegion *LHSR = getBaseRegionFromExpr(DRE, C);
          if (LHSR && LHSR == R)
            return true; // then-branch assigns to the pointer variable itself
        }
      }
    }

    for (const Stmt *Child : Cur->children())
      if (Child) Worklist.push_back(Child);
  }

  return false;
}

bool SAGenTestChecker::isLockAcquire(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  static const char *LockNames[] = {
    "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
    "mutex_lock", "rt_mutex_lock", "raw_spin_lock"
  };

  for (const char *Name : LockNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockRelease(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  static const char *UnlockNames[] = {
    "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
    "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock"
  };

  for (const char *Name : UnlockNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

unsigned SAGenTestChecker::getFrameLockDepth(ProgramStateRef State, const StackFrameContext *SFC) const {
  if (!SFC) return 0;
  if (const unsigned *D = State->get<FrameLockDepthMap>(SFC))
    return *D;
  return 0;
}

ProgramStateRef SAGenTestChecker::setFrameLockDepth(ProgramStateRef State, const StackFrameContext *SFC, unsigned Depth) const {
  if (!SFC) return State;
  if (Depth == 0)
    return State->remove<FrameLockDepthMap>(SFC);
  return State->set<FrameLockDepthMap>(SFC, Depth);
}

bool SAGenTestChecker::stmtDerefsAnyPtr(const Stmt *S, CheckerContext &C, const MemRegion *&PtrOut) const {
  PtrOut = nullptr;
  if (!S) return false;

  // Look for "ptr->field"
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Base->IgnoreParenImpCasts())) {
        PtrOut = getBaseRegionFromExpr(DRE, C);
        if (PtrOut) return true;
      }
    }
  }

  // Look for "*ptr"
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        PtrOut = getBaseRegionFromExpr(DRE, C);
        if (PtrOut) return true;
      }
    }
  }

  // Look for "ptr[idx]"
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      PtrOut = getBaseRegionFromExpr(DRE, C);
      if (PtrOut) return true;
    }
  }

  return false;
}

bool SAGenTestChecker::isFalsePositive(const Stmt *Then, const MemRegion *R, CheckerContext &C) const {
  // Heuristics: If the then-branch writes to the pointer itself (fixing it),
  // we shouldn't consider it a log-and-continue bug.
  if (thenWritesToVar(Then, R, C))
    return true;
  return false;
}

void SAGenTestChecker::reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  if (!BT)
    BT = std::make_unique<BugType>(C.getCheckName(),
                                   "Invalid check then deref under lock",
                                   "Concurrency");
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

  const Stmt *Then = IS->getThen();

  const MemRegion *R = extractNullCheckedPointer(Cond, C);
  if (!R)
    return;

  // Require that the then-branch logs something to be considered "log-and-continue".
  if (!containsLoggingCall(Then, C))
    return;

  // If then-branch contains early exit, it's OK.
  if (thenHasEarlyExit(Then, C))
    return;

  // Filter out fixes like "if (!ptr) ptr = default;" to avoid false positives.
  if (isFalsePositive(Then, R, C))
    return;

  ProgramStateRef State = C.getState();
  const StackFrameContext *SFC = C.getStackFrame();
  // Only care if we are currently outside a lock in this frame.
  if (getFrameLockDepth(State, SFC) > 0)
    return;

  // Mark this pointer as suspicious in this frame.
  State = State->set<SuspiciousNoLockMap>(R, SFC);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const StackFrameContext *SFC = C.getStackFrame();

  if (isLockAcquire(Call, C)) {
    unsigned Depth = getFrameLockDepth(State, SFC);
    State = setFrameLockDepth(State, SFC, Depth + 1);

    // Move regions from SuspiciousNoLockMap to SuspiciousAfterLockMap for this frame only.
    llvm::SmallVector<const MemRegion*, 8> ToMove;
    auto NoLock = State->get<SuspiciousNoLockMap>();
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      const MemRegion *R = I->first;
      const StackFrameContext *Origin = I->second;
      if (Origin == SFC)
        ToMove.push_back(R);
    }
    for (const MemRegion *R : ToMove) {
      State = State->set<SuspiciousAfterLockMap>(R, SFC);
      State = State->remove<SuspiciousNoLockMap>(R);
    }

    C.addTransition(State);
    return;
  }

  if (isLockRelease(Call, C)) {
    unsigned Depth = getFrameLockDepth(State, SFC);
    if (Depth > 0)
      State = setFrameLockDepth(State, SFC, Depth - 1);
    else
      State = setFrameLockDepth(State, SFC, 0);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // For calls that are known to dereference pointer arguments, check if any match our tracked pointer.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();
  const StackFrameContext *SFC = C.getStackFrame();
  unsigned Depth = getFrameLockDepth(State, SFC);
  if (Depth == 0)
    return; // Only care if currently under lock in this frame.

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

    if (const StackFrameContext *const *Stored = State->get<SuspiciousAfterLockMap>(MR)) {
      if (*Stored == SFC) {
        reportDerefBug(Call.getOriginExpr(), MR, C);
        State = State->remove<SuspiciousAfterLockMap>(MR);
        C.addTransition(State);
      }
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const StackFrameContext *SFC = C.getStackFrame();
  unsigned Depth = getFrameLockDepth(State, SFC);
  if (Depth == 0)
    return; // Only report derefs under lock.

  const MemRegion *DerefR = nullptr;
  if (!stmtDerefsAnyPtr(S, C, DerefR) || !DerefR)
    return;

  if (const StackFrameContext *const *Stored = State->get<SuspiciousAfterLockMap>(DerefR)) {
    if (*Stored == SFC) {
      reportDerefBug(S, DerefR, C);
      State = State->remove<SuspiciousAfterLockMap>(DerefR);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Cleanup frame-specific state when leaving the function.
  ProgramStateRef State = C.getState();
  const StackFrameContext *SFC = C.getStackFrame();

  // Remove any entries bound to this frame to keep state lean.
  auto NoLock = State->get<SuspiciousNoLockMap>();
  for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
    if (I->second == SFC)
      State = State->remove<SuspiciousNoLockMap>(I->first);
  }
  auto After = State->get<SuspiciousAfterLockMap>();
  for (auto I = After.begin(), E = After.end(); I != E; ++I) {
    if (I->second == SFC)
      State = State->remove<SuspiciousAfterLockMap>(I->first);
  }
  State = State->remove<FrameLockDepthMap>(SFC);

  C.addTransition(State);
}

// Template helper definitions

template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C) {
  if (!S) return nullptr;
  const Stmt *Cur = S;
  auto &PMC = C.getASTContext().getParentMapContext();

  while (Cur) {
    auto Parents = PMC.getParents(*Cur);
    if (Parents.empty())
      return nullptr;

    const DynTypedNode &Node = Parents[0];
    if (const T *Res = Node.get<T>())
      return Res;

    if (const Stmt *PS = Node.get<Stmt>())
      Cur = PS;
    else
      return nullptr;
  }
  return nullptr;
}

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S) {
  if (!S) return nullptr;
  llvm::SmallVector<const Stmt*, 16> Worklist;
  Worklist.push_back(S);
  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (!Cur) continue;
    if (const T *Res = dyn_cast<T>(Cur))
      return Res;
    for (const Stmt *Child : Cur->children())
      if (Child) Worklist.push_back(Child);
  }
  return nullptr;
}

} // end anonymous namespace

// Provide a default (empty) definition to avoid undefined symbol issues if not supplied externally.
llvm::SmallVector<KnownDerefFunction, 4> DerefTable;

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects null-check that only logs without abort, then dereferences under lock",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
