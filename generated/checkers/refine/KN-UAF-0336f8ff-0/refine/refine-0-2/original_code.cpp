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

// We keep a directed mapping from pointer-typed storage (Var/Field) to the
// pointee region only if needed later. Currently, we avoid chasing aliases
// in reports to prevent false positives.
// (Kept for potential future use; no alias chasing is currently performed.)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrPointsTo, const MemRegion*, const MemRegion*)

namespace {

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

  static bool devIsFreed(ProgramStateRef State, const MemRegion *DevBase);

  // Return the dev region if R is within some priv region that maps to a dev.
  // OutPrivBase, if non-null, receives the matching priv base region.
  static const MemRegion *findDevForPrivDerivedRegion(ProgramStateRef State,
                                                      const MemRegion *R,
                                                      const MemRegion **OutPrivBase = nullptr);

  static bool knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                    llvm::SmallVectorImpl<unsigned> &OutIdx);

  static bool isWithinRegion(const MemRegion *R, const MemRegion *Container);

  // FP filter: accessing a pointer-typed lvalue (reading/writing the pointer
  // variable or field itself) is not a dereference of its pointee.
  static bool isPointerLValueRegion(const MemRegion *R);

  void reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
  void reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const;
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

bool SAGenTestChecker::devIsFreed(ProgramStateRef State, const MemRegion *DevBase) {
  if (!DevBase) return false;
  return State->contains<FreedDevs>(DevBase);
}

const MemRegion *SAGenTestChecker::findDevForPrivDerivedRegion(ProgramStateRef State,
                                                               const MemRegion *R,
                                                               const MemRegion **OutPrivBase) {
  if (!R) return nullptr;

  // Walk up ancestor chain from R, looking for a priv base that we recorded.
  // We intentionally do NOT follow arbitrary alias maps to avoid false positives.
  const MemRegion *Cur = R;
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur && Visited.insert(Cur).second) {
    // Try exact key in the priv->dev map.
    if (const MemRegion *const *DevBase = State->get<Priv2DevMap>(Cur)) {
      if (OutPrivBase)
        *OutPrivBase = Cur;
      return *DevBase;
    }

    // For subregions, climb to the super-region.
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
  // Common Linux helpers that synchronously dereference work/timer structures.
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

  // Fallback: textual match if identifier not available.
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

    // Try to get the region representing the returned pointer's pointee.
    const SVal RetV = Call.getReturnValue();
    const MemRegion *PrivReg = RetV.getAsRegion(); // Pointee region for pointer returns.

    // Report if netdev_priv(dev) is called after free(dev)
    if (DevBase && devIsFreed(State, DevBase)) {
      reportUAFAtCall(Call, C, "netdev_priv(dev) after free_netdev");
      return;
    }

    // Record mapping priv(pointee) -> dev
    if (PrivReg && DevBase) {
      const MemRegion *PrivBase = getBaseRegionOrSelf(PrivReg);
      State = State->set<Priv2DevMap>(PrivBase, DevBase);
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
      reportUAFAtCall(Call, C, "Use of netdev priv after free_netdev");
      return;
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  // If we are reading or writing a pointer-typed lvalue (like "port->user"),
  // this is not a dereference of its pointee; ignore to avoid false positives.
  if (isPointerLValueRegion(R))
    return;

  ProgramStateRef State = C.getState();

  // See if the accessed region is within a tracked netdev priv region.
  const MemRegion *PrivBase = nullptr;
  const MemRegion *DevBase = findDevForPrivDerivedRegion(State, R, &PrivBase);
  if (!DevBase || !PrivBase)
    return;

  // Double-check we are truly touching memory inside the priv object.
  if (!isWithinRegion(R, PrivBase))
    return;

  if (devIsFreed(State, DevBase)) {
    reportUAFAtStmt(S, C, "Use of netdev priv after free_netdev");
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Optionally track pointer variable -> pointee mapping (directed), but
  // do not chase it in reporting to avoid FPs.
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;

  // Only track for pointer-typed lvalues.
  const auto *TVR = dyn_cast<TypedValueRegion>(LHS);
  if (!TVR || !TVR->getValueType()->isPointerType())
    return;

  const MemRegion *Pointee = Val.getAsRegion();
  if (!Pointee)
    return;

  // Map pointer storage region to the pointee region (directed).
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
