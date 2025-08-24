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

REGISTER_MAP_WITH_PROGRAMSTATE(Priv2DevMap, const MemRegion*, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(FreedDevs, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::Location,
                                        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-free (net_device private)", "Memory error")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name);
      static const MemRegion *getBaseRegionOrSelf(const MemRegion *R);
      static const MemRegion *resolveAlias(ProgramStateRef State, const MemRegion *R);
      static const MemRegion *exprToBaseRegion(const Expr *E, CheckerContext &C);
      static const MemRegion *privBaseToDevBase(ProgramStateRef State, const MemRegion *PrivBase);
      static bool devIsFreed(ProgramStateRef State, const MemRegion *DevBase);

      static bool knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                        llvm::SmallVectorImpl<unsigned> &OutIdx);

      void reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
      void reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const;
};

bool SAGenTestChecker::callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name) {
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

const MemRegion *SAGenTestChecker::resolveAlias(ProgramStateRef State, const MemRegion *R) {
  if (!R) return nullptr;
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  const MemRegion *Cur = R;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break; // cycle
    const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur);
    const MemRegion *Next = NextPtr ? *NextPtr : nullptr;
    if (!Next)
      break;
    Cur = Next;
  }
  return Cur ? Cur : R;
}

const MemRegion *SAGenTestChecker::exprToBaseRegion(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = getBaseRegionOrSelf(MR);
  ProgramStateRef State = C.getState();
  MR = resolveAlias(State, MR);
  return MR;
}

const MemRegion *SAGenTestChecker::privBaseToDevBase(ProgramStateRef State, const MemRegion *PrivBase) {
  if (!PrivBase) return nullptr;
  const MemRegion *const *MappedPtr = State->get<Priv2DevMap>(PrivBase);
  const MemRegion *Mapped = MappedPtr ? *MappedPtr : nullptr;
  if (!Mapped) return nullptr;
  return resolveAlias(State, Mapped);
}

bool SAGenTestChecker::devIsFreed(ProgramStateRef State, const MemRegion *DevBase) {
  if (!DevBase) return false;
  return State->contains<FreedDevs>(DevBase);
}

bool SAGenTestChecker::knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                             llvm::SmallVectorImpl<unsigned> &OutIdx) {
  // Functions that dereference their argument(s) which typically point
  // to work/timer structures stored in netdev private data.
  // We target index 0 for these common kernel helpers.
  static const char *Names[] = {
    "cancel_work_sync",
    "cancel_delayed_work_sync",
    "flush_work",
    "flush_delayed_work",
    "del_timer_sync",
    "del_timer",
  };
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  bool Found = false;
  for (const char *N : Names) {
    if (ExprHasName(OriginExpr, N, C)) {
      OutIdx.push_back(0);
      Found = true;
      break;
    }
  }
  return Found;
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
        DevBase = getBaseRegionOrSelf(DevBase);
        DevBase = resolveAlias(State, DevBase);
        State = State->add<FreedDevs>(DevBase);
        C.addTransition(State);
      }
    }
    return;
  }

  // Learn priv->dev mapping for netdev_priv(dev).
  if (callHasName(Call, C, "netdev_priv")) {
    // Get dev base
    const Expr *DevE = (Call.getNumArgs() >= 1) ? Call.getArgExpr(0) : nullptr;
    const MemRegion *DevBase = exprToBaseRegion(DevE, C);

    // Get return region (priv)
    const Expr *Origin = Call.getOriginExpr();
    const MemRegion *RetReg = Origin ? getMemRegionFromExpr(Origin, C) : nullptr;
    if (!RetReg) {
      // Fallback to using return value region if available
      RetReg = Call.getReturnValue().getAsRegion();
    }
    if (RetReg)
      RetReg = getBaseRegionOrSelf(RetReg);
    if (RetReg)
      RetReg = resolveAlias(State, RetReg);

    // If dev already freed, flag "netdev_priv(dev) after free_netdev".
    if (DevBase && devIsFreed(State, DevBase)) {
      reportUAFAtCall(Call, C, "netdev_priv(dev) after free_netdev");
      return;
    }

    // Record mapping priv -> dev
    if (RetReg && DevBase) {
      State = State->set<Priv2DevMap>(RetReg, DevBase);
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
    const MemRegion *ArgBase = exprToBaseRegion(ArgE, C);
    if (!ArgBase)
      continue;

    const MemRegion *DevBase = privBaseToDevBase(State, ArgBase);
    if (!DevBase)
      continue;

    if (devIsFreed(State, DevBase)) {
      reportUAFAtCall(Call, C, "Use of netdev priv after free_netdev");
      return;
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Catch direct dereferences of priv-derived memory after free_netdev().
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Base = getBaseRegionOrSelf(R);
  Base = resolveAlias(State, Base);

  const MemRegion *DevBase = privBaseToDevBase(State, Base);
  if (!DevBase)
    return;

  if (devIsFreed(State, DevBase)) {
    reportUAFAtStmt(S, C, "Use of netdev priv after free_netdev");
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = getBaseRegionOrSelf(LHS);
  LHS = resolveAlias(State, LHS);
  if (!LHS)
    return;

  const MemRegion *RHS = Val.getAsRegion();
  if (!RHS)
    return;
  RHS = getBaseRegionOrSelf(RHS);
  RHS = resolveAlias(State, RHS);
  if (!RHS)
    return;

  // Record alias both directions to simplify lookups.
  State = State->set<PtrAliasMap>(LHS, RHS);
  State = State->set<PtrAliasMap>(RHS, LHS);

  // Propagate priv->dev mapping across alias
  if (const MemRegion *const *DevBase = State->get<Priv2DevMap>(RHS)) {
    State = State->set<Priv2DevMap>(LHS, *DevBase);
  }
  if (const MemRegion *const *DevBase2 = State->get<Priv2DevMap>(LHS)) {
    State = State->set<Priv2DevMap>(RHS, *DevBase2);
  }

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
