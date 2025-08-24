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

// ---------------- Utility Functions (provided) ----------------

template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C) {
  if (!S) return nullptr;
  const Stmt *Cur = S;
  while (Cur) {
    auto Parents = C.getASTContext().getParents(*Cur);
    if (Parents.empty())
      break;
    if (const Stmt *P = Parents[0].get<Stmt>()) {
      if (const auto *Res = dyn_cast<T>(P))
        return Res;
      Cur = P;
      continue;
    }
    // If parent is not a Stmt (e.g., Decl), stop.
    break;
  }
  return nullptr;
}

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S) {
  if (!S) return nullptr;
  if (const auto *R = dyn_cast<T>(S))
    return R;
  for (const Stmt *Child : S->children()) {
    if (const T *R = findSpecificTypeInChildren<T>(Child))
      return R;
  }
  return nullptr;
}

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
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

// A small table of well-known C functions that dereference certain parameters.
static const KnownDerefFunction DerefTable[] = {
  {"memcpy", {0, 1}},
  {"memmove", {0, 1}},
  {"memset", {0}},
  {"strcpy", {0, 1}},
  {"strncpy", {0, 1}},
  {"strcat", {0, 1}},
  {"strncat", {0, 1}},
  {"strlen", {0}},
  {"strcmp", {0, 1}},
  {"strncmp", {0, 1}},
  {"bcopy", {0, 1}},
  {"bzero", {0}},
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
      // Lock helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;

      // Pointer/condition helpers
      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      // Heuristics for deref/use
      bool stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                const ProgramStateRef &State,
                                const MemRegion *&TrackedPtrOut) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;

      // Logging/early-exit helpers
      bool containsLoggingCall(const Stmt *S, CheckerContext &C) const;
      static bool isLoggingName(StringRef Name);

      // New: precise identification of which branch is the "invalid" branch
      bool getInvalidPtrAndBranch(const Expr *Cond, CheckerContext &C,
                                  const MemRegion *&PtrMR, bool &InvalidIsThen) const;

      // Early-exit detection
      bool thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const;
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

static const MemRegion *getPtrFromSimpleExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (DRE->getType()->isAnyPointerType()) {
      const MemRegion *MR = getMemRegionFromExpr(DRE, C);
      if (MR) return MR->getBaseRegion();
    }
  }
  return nullptr;
}

// Returns true if E being true implies the pointer is invalid (NULL),
// sets R to that pointer region.
static bool impliesInvalidOnThen(const Expr *E, CheckerContext &C, const MemRegion *&R) {
  R = nullptr;
  if (!E) return false;
  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const MemRegion *MR = getPtrFromSimpleExpr(UO->getSubExpr(), C)) {
        R = MR;
        return true;
      }
    }
    return false;
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    auto Op = BO->getOpcode();

    if (Op == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (isNullLikeExpr(L, C)) {
        if (const MemRegion *MR = getPtrFromSimpleExpr(RHS, C)) {
          R = MR; return true;
        }
      }
      if (isNullLikeExpr(RHS, C)) {
        if (const MemRegion *MR = getPtrFromSimpleExpr(L, C)) {
          R = MR; return true;
        }
      }
      return false;
    }

    if (Op == BO_NE) {
      // ptr != NULL => true branch implies ptr is valid, so not invalid-on-Then
      return false;
    }

    if (Op == BO_LOr || Op == BO_LAnd) {
      const MemRegion *R1 = nullptr;
      if (impliesInvalidOnThen(BO->getLHS(), C, R1)) { R = R1; return true; }
      const MemRegion *R2 = nullptr;
      if (impliesInvalidOnThen(BO->getRHS(), C, R2)) { R = R2; return true; }
      return false;
    }

    return false;
  }

  // A plain "ptr" does not imply invalid-on-Then.
  return false;
}

// Returns true if E being false (i.e., Else-branch) implies the pointer is invalid (NULL),
// sets R to that pointer region. We conservatively handle common patterns only.
static bool impliesInvalidOnElse(const Expr *E, CheckerContext &C, const MemRegion *&R) {
  R = nullptr;
  if (!E) return false;
  E = E->IgnoreParenImpCasts();

  // "if (ptr)" => Else means ptr is NULL.
  if (const MemRegion *MR = getPtrFromSimpleExpr(E, C)) {
    R = MR;
    return true;
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    auto Op = BO->getOpcode();

    if (Op == BO_NE) {
      // ptr != NULL => Else means ptr is NULL
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (isNullLikeExpr(L, C)) {
        if (const MemRegion *MR = getPtrFromSimpleExpr(RHS, C)) {
          R = MR; return true;
        }
      }
      if (isNullLikeExpr(RHS, C)) {
        if (const MemRegion *MR = getPtrFromSimpleExpr(L, C)) {
          R = MR; return true;
        }
      }
      return false;
    }

    if (Op == BO_LAnd) {
      // if (ptr && other) => Else can happen when ptr is NULL
      const MemRegion *R1 = nullptr;
      if (impliesInvalidOnElse(BO->getLHS(), C, R1)) { R = R1; return true; }
      const MemRegion *R2 = nullptr;
      if (impliesInvalidOnElse(BO->getRHS(), C, R2)) { R = R2; return true; }
      return false;
    }

    // Be conservative: do not claim invalid-on-Else for "||" to avoid FPs.
    return false;
  }

  return false;
}

bool SAGenTestChecker::getInvalidPtrAndBranch(const Expr *Cond, CheckerContext &C,
                                              const MemRegion *&PtrMR, bool &InvalidIsThen) const {
  PtrMR = nullptr;
  InvalidIsThen = true;

  const MemRegion *RThen = nullptr;
  if (impliesInvalidOnThen(Cond, C, RThen) && RThen) {
    PtrMR = RThen;
    InvalidIsThen = true;
    return true;
  }

  const MemRegion *RElse = nullptr;
  if (impliesInvalidOnElse(Cond, C, RElse) && RElse) {
    PtrMR = RElse;
    InvalidIsThen = false;
    return true;
  }

  return false;
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
                                            const MemRegion *&TrackedPtrOut) const {
  TrackedPtrOut = nullptr;
  if (!S) return false;

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

  const MemRegion *R = nullptr;
  bool InvalidIsThen = true;
  if (!getInvalidPtrAndBranch(Cond, C, R, InvalidIsThen) || !R)
    return;

  const Stmt *InvalidBranch = InvalidIsThen ? IS->getThen() : IS->getElse();
  if (!InvalidBranch)
    return;

  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();

  // If inside the lock and we see re-validation with early exit on the same pointer, clear suspicion.
  if (Depth > 0) {
    if (thenHasEarlyExit(InvalidBranch, C)) {
      State = State->remove<SuspiciousAfterLockSet>(R);
      C.addTransition(State);
    }
    return;
  }

  // Outside lock: only consider the invalid branch. It must log and must not abort.
  if (thenHasEarlyExit(InvalidBranch, C))
    return;

  if (!containsLoggingCall(InvalidBranch, C))
    return;

  // Mark this pointer as suspicious: invalid-checked, log-only, and not under lock.
  State = State->add<SuspiciousNoLockSet>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isLockAcquire(Call, C)) {
    int Depth = State->get<LockDepth>();
    State = State->set<LockDepth>(Depth + 1);

    auto NoLock = State->get<SuspiciousNoLockSet>();
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      const MemRegion *R = *I;
      State = State->add<SuspiciousAfterLockSet>(R);
    }
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
