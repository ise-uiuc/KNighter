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
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the framework snippet
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

// Program state: priv(pointee base) -> dev(pointee base).
REGISTER_MAP_WITH_PROGRAMSTATE(Priv2DevMap, const MemRegion*, const MemRegion*)

// Legacy set (unused after refinement but kept for compatibility, not removed).
REGISTER_SET_WITH_PROGRAMSTATE(FreedDevs, const MemRegion*)

// Directed map: pointer-typed storage region -> pointee region (optional tracking).
REGISTER_MAP_WITH_PROGRAMSTATE(PtrPointsTo, const MemRegion*, const MemRegion*)

// Epoch-based lifetime tracking for dev objects.
// DevEpochMap: current allocation epoch for a dev pointee region.
// FreedEpochMap: last epoch at which the dev was freed.
REGISTER_MAP_WITH_PROGRAMSTATE(DevEpochMap, const MemRegion*, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(FreedEpochMap, const MemRegion*, unsigned)

namespace {

static bool containsStmt(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target)
    return false;
  if (Root == Target)
    return true;
  for (const Stmt *Child : Root->children()) {
    if (containsStmt(Child, Target))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::Location,
                                        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use-after-free (net_device private)", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name);
  static const MemRegion *getBaseRegionOrSelf(const MemRegion *R);
  static const MemRegion *exprToRegion(const Expr *E, CheckerContext &C);
  static const MemRegion *exprToBaseRegion(const Expr *E, CheckerContext &C);

  static unsigned getDevEpoch(ProgramStateRef State, const MemRegion *DevBase);
  static unsigned getFreedEpoch(ProgramStateRef State, const MemRegion *DevBase);
  static bool devIsFreed(ProgramStateRef State, const MemRegion *DevBase);

  static const MemRegion *findDevForPrivDerivedRegion(ProgramStateRef State,
                                                      const MemRegion *R,
                                                      const MemRegion **OutPrivBase = nullptr);

  static bool knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                    llvm::SmallVectorImpl<unsigned> &OutIdx);

  static bool knownWorkOrTimerDerefCE(const CallExpr *CE, CheckerContext &C,
                                      llvm::SmallVectorImpl<unsigned> &OutIdx);

  static bool isWithinRegion(const MemRegion *R, const MemRegion *Container);
  static bool isPointerLValueRegion(const MemRegion *R);

  static bool findEnclosingCallArg(const Stmt *S, CheckerContext &C,
                                   const CallExpr *&OutCE, unsigned &OutArgIdx);

  static bool isAllocNetdevLike(const CallEvent &Call, CheckerContext &C);

  void reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
  void reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const;

  // Optional FP guard hook.
  static bool isFalsePositive(const Stmt *S, CheckerContext &C) {
    // Currently unused placeholder for future fine-grained heuristics.
    (void)S; (void)C;
    return false;
  }
};

bool SAGenTestChecker::callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  // Fallback on textual check if no identifier (macros, etc.)
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, Name, C);
}

const MemRegion *SAGenTestChecker::getBaseRegionOrSelf(const MemRegion *R) {
  if (!R) return nullptr;
  const MemRegion *Prev = nullptr;
  const MemRegion *Cur = R;
  while (Cur && Cur != Prev) {
    Prev = Cur;
    Cur = Cur->getBaseRegion();
  }
  return Cur;
}

const MemRegion *SAGenTestChecker::exprToRegion(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  return getMemRegionFromExpr(E, C);
}

const MemRegion *SAGenTestChecker::exprToBaseRegion(const Expr *E, CheckerContext &C) {
  const MemRegion *MR = exprToRegion(E, C);
  if (!MR) return nullptr;
  return getBaseRegionOrSelf(MR);
}

unsigned SAGenTestChecker::getDevEpoch(ProgramStateRef State, const MemRegion *DevBase) {
  if (!DevBase) return 0;
  if (const unsigned *E = State->get<DevEpochMap>(DevBase))
    return *E;
  return 0;
}

unsigned SAGenTestChecker::getFreedEpoch(ProgramStateRef State, const MemRegion *DevBase) {
  if (!DevBase) return 0;
  if (const unsigned *E = State->get<FreedEpochMap>(DevBase))
    return *E;
  return 0;
}

bool SAGenTestChecker::devIsFreed(ProgramStateRef State, const MemRegion *DevBase) {
  if (!DevBase)
    return false;
  unsigned Cur = getDevEpoch(State, DevBase);
  unsigned Freed = getFreedEpoch(State, DevBase);
  // The dev is considered freed only if the last freed epoch equals the current allocation epoch.
  return (Cur != 0 || Freed != 0) && (Cur == Freed);
}

const MemRegion *SAGenTestChecker::findDevForPrivDerivedRegion(ProgramStateRef State,
                                                               const MemRegion *R,
                                                               const MemRegion **OutPrivBase) {
  if (!R) return nullptr;

  // Walk up ancestor chain from R, looking for a priv base that we recorded.
  const MemRegion *Cur = R;
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur && Visited.insert(Cur).second) {
    if (const MemRegion *const *DevBase = State->get<Priv2DevMap>(Cur)) {
      if (OutPrivBase)
        *OutPrivBase = Cur;
      return *DevBase;
    }

    if (const auto *SR = dyn_cast<SubRegion>(Cur)) {
      Cur = SR->getSuperRegion();
      continue;
    }
    break;
  }

  if (OutPrivBase)
    *OutPrivBase = nullptr;
  return nullptr;
}

bool SAGenTestChecker::knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                             llvm::SmallVectorImpl<unsigned> &OutIdx) {
  static const char *Names[] = {
      "cancel_work_sync",
      "cancel_delayed_work_sync",
      "flush_work",
      "flush_delayed_work",
      "del_timer_sync",
      "del_timer",
  };

  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Fn = ID->getName();
    for (const char *N : Names) {
      if (Fn.equals(N)) {
        OutIdx.push_back(0);
        return true;
      }
    }
  }

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  for (const char *N : Names) {
    if (ExprHasName(OriginExpr, N, C)) {
      OutIdx.push_back(0);
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::knownWorkOrTimerDerefCE(const CallExpr *CE, CheckerContext &C,
                                               llvm::SmallVectorImpl<unsigned> &OutIdx) {
  if (!CE)
    return false;

  // Try identifier of direct callee decl.
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (const IdentifierInfo *ID = FD->getIdentifier()) {
      StringRef Fn = ID->getName();
      static const char *Names[] = {
          "cancel_work_sync",
          "cancel_delayed_work_sync",
          "flush_work",
          "flush_delayed_work",
          "del_timer_sync",
          "del_timer",
      };
      for (const char *N : Names) {
        if (Fn.equals(N)) {
          OutIdx.push_back(0);
          return true;
        }
      }
    }
  }

  // Fallback to textual match on callee subexpression.
  if (const Expr *Callee = CE->getCallee()) {
    static const char *Names[] = {
        "cancel_work_sync",
        "cancel_delayed_work_sync",
        "flush_work",
        "flush_delayed_work",
        "del_timer_sync",
        "del_timer",
    };
    for (const char *N : Names) {
      if (ExprHasName(Callee, N, C)) {
        OutIdx.push_back(0);
        return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::isWithinRegion(const MemRegion *R, const MemRegion *Container) {
  if (!R || !Container) return false;
  if (R == Container) return true;
  if (const auto *SR = dyn_cast<SubRegion>(R))
    return SR->isSubRegionOf(Container);
  return false;
}

bool SAGenTestChecker::isPointerLValueRegion(const MemRegion *R) {
  if (!R) return false;
  const auto *TVR = dyn_cast<TypedValueRegion>(R);
  if (!TVR)
    return false;
  QualType Ty = TVR->getValueType();
  return Ty->isPointerType();
}

bool SAGenTestChecker::findEnclosingCallArg(const Stmt *S, CheckerContext &C,
                                            const CallExpr *&OutCE, unsigned &OutArgIdx) {
  OutCE = findSpecificTypeInParents<CallExpr>(S, C);
  if (!OutCE)
    return false;

  unsigned NumArgs = OutCE->getNumArgs();
  for (unsigned i = 0; i < NumArgs; ++i) {
    const Expr *Arg = OutCE->getArg(i);
    if (!Arg)
      continue;
    // Precise structural containment check: is S inside the AST subtree of this argument?
    if (containsStmt(Arg, S)) {
      OutArgIdx = i;
      return true;
    }
  }

  return false;
}

bool SAGenTestChecker::isAllocNetdevLike(const CallEvent &Call, CheckerContext &C) {
  // Common Linux netdev allocators. Keep conservative superset, harmless if missed.
  static const char *Names[] = {
      "alloc_netdev", "alloc_netdev_mqs",
      "alloc_etherdev", "alloc_etherdev_mq",
      "alloc_candev", "alloc_candev_mqs",
      "alloc_fcdev",
  };

  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Fn = ID->getName();
    for (const char *N : Names) {
      if (Fn.equals(N))
        return true;
    }
  }

  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  for (const char *N : Names) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Record dev free when free_netdev(dev) is called.
  if (callHasName(Call, C, "free_netdev")) {
    if (Call.getNumArgs() >= 1) {
      const Expr *DevE = Call.getArgExpr(0);
      const MemRegion *DevBase = exprToBaseRegion(DevE, C);
      if (DevBase) {
        unsigned CurEpoch = getDevEpoch(State, DevBase);
        // Mark freed at current epoch.
        State = State->set<FreedEpochMap>(DevBase, CurEpoch);
        // Keep legacy set updated to avoid breaking any other logic accidentally relying on it.
        State = State->add<FreedDevs>(DevBase);
        C.addTransition(State);
      }
    }
    return;
  }

  // Learn priv->dev mapping for netdev_priv(dev).
  if (callHasName(Call, C, "netdev_priv")) {
    const Expr *DevE = (Call.getNumArgs() >= 1) ? Call.getArgExpr(0) : nullptr;
    const MemRegion *DevBase = exprToBaseRegion(DevE, C);

    const SVal RetV = Call.getReturnValue();
    const MemRegion *PrivReg = RetV.getAsRegion(); // pointee region for pointer return

    // Report if netdev_priv(dev) is called after free(dev) (same epoch).
    if (DevBase && devIsFreed(State, DevBase)) {
      reportUAFAtCall(Call, C, "netdev_priv(dev) after free_netdev");
      return;
    }

    // Record mapping priv(pointee base) -> dev(pointee base).
    if (PrivReg && DevBase) {
      const MemRegion *PrivBase = getBaseRegionOrSelf(PrivReg);
      State = State->set<Priv2DevMap>(PrivBase, DevBase);
      C.addTransition(State);
    }
    return;
  }

  // Detect netdev allocations and advance epoch for the returned dev region.
  if (isAllocNetdevLike(Call, C)) {
    const SVal RetV = Call.getReturnValue();
    const MemRegion *DevReg = RetV.getAsRegion(); // pointee region of returned pointer
    const MemRegion *DevBase = getBaseRegionOrSelf(DevReg);
    if (DevBase) {
      unsigned CurEpoch = getDevEpoch(State, DevBase);
      unsigned NewEpoch = CurEpoch + 1;
      State = State->set<DevEpochMap>(DevBase, NewEpoch);
      // New allocation resets any stale freed marker for this region.
      State = State->remove<FreedEpochMap>(DevBase);
      // Also remove legacy FreedDevs entry if any.
      State = State->remove<FreedDevs>(DevBase);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect uses of priv-derived pointers after free_netdev() via known-deref functions.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!knownWorkOrTimerDeref(Call, C, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    const MemRegion *ArgReg = exprToRegion(ArgE, C);
    if (!ArgReg)
      continue;

    const MemRegion *DevBase = findDevForPrivDerivedRegion(State, ArgReg);
    if (!DevBase)
      continue;

    if (devIsFreed(State, DevBase)) {
      if (!isFalsePositive(Call.getOriginExpr(), C))
        reportUAFAtCall(Call, C, "Use of netdev priv after free_netdev");
      return;
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only consider loads/stores that happen as part of arguments to functions
  // that are known to synchronously dereference work/timer objects (cancel_work_sync, etc.).
  const CallExpr *CE = nullptr;
  unsigned ArgIdx = 0;
  if (!findEnclosingCallArg(S, C, CE, ArgIdx))
    return;

  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!knownWorkOrTimerDerefCE(CE, C, DerefParams))
    return;

  // Only proceed if the accessed location belongs to an argument that
  // is known to be dereferenced by the callee.
  bool Matches = llvm::is_contained(DerefParams, ArgIdx);
  if (!Matches)
    return;

  const Expr *ArgE = CE->getArg(ArgIdx);
  if (!ArgE)
    return;

  const MemRegion *ArgReg = exprToRegion(ArgE, C);
  if (!ArgReg)
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *PrivBase = nullptr;
  const MemRegion *DevBase = findDevForPrivDerivedRegion(State, ArgReg, &PrivBase);
  if (!DevBase || !PrivBase)
    return;

  if (devIsFreed(State, DevBase)) {
    if (!isFalsePositive(CE, C))
      reportUAFAtStmt(CE, C, "Use of netdev priv after free_netdev");
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Optionally track pointer variable -> pointee mapping (directed), but
  // do not chase it in reporting to avoid FPs.
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;

  const auto *TVR = dyn_cast<TypedValueRegion>(LHS);
  if (!TVR || !TVR->getValueType()->isPointerType())
    return;

  const MemRegion *Pointee = Val.getAsRegion();
  if (!Pointee)
    return;

  State = State->set<PtrPointsTo>(LHS, getBaseRegionOrSelf(Pointee));
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of netdev private data after free_netdev (e.g., cancel_work_sync on priv fields)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
