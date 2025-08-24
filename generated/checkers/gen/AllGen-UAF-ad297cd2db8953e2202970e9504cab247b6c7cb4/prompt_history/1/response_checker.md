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

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(PtrToNetdev, const MemRegion*, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(NetdevFreedMap, const MemRegion*, char)

namespace {

class SAGenTestChecker : public Checker<
    check::Bind,
    check::PreCall,
    check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "use-after-free of net_device private data", "Memory Management")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C);
      static StringRef getCalleeName(const CallEvent &Call);
      static const MemRegion *getArgRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C);

      static const MemRegion *getLHSRegionFromBind(SVal Loc);
      static const MemRegion *getRHSRegionFromBind(SVal Val);

      static const Expr *getRootBaseExprOfMemberChain(const Expr *E);
      static const MemRegion *getMemberBasePtrRegion(const Stmt *S, CheckerContext &C);
      static const MemRegion *argContainsMemberBasePtrRegion(const Expr *Arg, CheckerContext &C);

      static const MemRegion *getOwnerNetdevForPtr(ProgramStateRef State, const MemRegion *PtrReg);
      static bool isNetdevFreed(ProgramStateRef State, const MemRegion *NetdevReg);

      void reportUAF(const Stmt *Trigger, const MemRegion *NetdevReg, CheckerContext &C) const;
};

// Implementation

bool SAGenTestChecker::isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, Name, C);
}

StringRef SAGenTestChecker::getCalleeName(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName();
  return StringRef();
}

const MemRegion *SAGenTestChecker::getArgRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) {
  if (Idx >= Call.getNumArgs())
    return nullptr;
  const Expr *ArgE = Call.getArgExpr(Idx);
  if (!ArgE)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

const MemRegion *SAGenTestChecker::getLHSRegionFromBind(SVal Loc) {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion *SAGenTestChecker::getRHSRegionFromBind(SVal Val) {
  const MemRegion *MR = Val.getAsRegion();
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const Expr *SAGenTestChecker::getRootBaseExprOfMemberChain(const Expr *E) {
  if (!E) return nullptr;
  const Expr *Base = E;
  // Walk down through member chains to find the root base expression (e.g., 'adpt' from 'adpt->phy.base')
  while (true) {
    const Expr *Cur = Base->IgnoreParenImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(Cur)) {
      Base = ME->getBase();
      continue;
    }
    break;
  }
  return Base;
}

const MemRegion *SAGenTestChecker::getMemberBasePtrRegion(const Stmt *S, CheckerContext &C) {
  if (!S) return nullptr;
  const MemberExpr *ME = findSpecificTypeInParents<MemberExpr>(S, C);
  if (!ME) return nullptr;

  const Expr *RootBase = getRootBaseExprOfMemberChain(ME);
  if (!RootBase) return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(RootBase, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion *SAGenTestChecker::argContainsMemberBasePtrRegion(const Expr *Arg, CheckerContext &C) {
  if (!Arg) return nullptr;
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg);
  if (!ME) return nullptr;

  const Expr *RootBase = getRootBaseExprOfMemberChain(ME);
  if (!RootBase) return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(RootBase, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion *SAGenTestChecker::getOwnerNetdevForPtr(ProgramStateRef State, const MemRegion *PtrReg) {
  if (!State || !PtrReg) return nullptr;
  return State->get<PtrToNetdev>(PtrReg);
}

bool SAGenTestChecker::isNetdevFreed(ProgramStateRef State, const MemRegion *NetdevReg) {
  if (!State || !NetdevReg) return false;
  const char *Val = State->get<NetdevFreedMap>(NetdevReg);
  return Val && *Val == 1;
}

void SAGenTestChecker::reportUAF(const Stmt *Trigger, const MemRegion *NetdevReg, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "use-after-free: net_device private data used after free_netdev()", N);
  if (Trigger)
    R->addRange(Trigger->getSourceRange());
  C.emitReport(std::move(R));
}

// Build map from private-data pointer to its owning net_device
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = getLHSRegionFromBind(Loc);
  if (!LHSReg) {
    return;
  }

  // Case A: LHS is assigned from netdev_priv(netdev)
  if (S) {
    const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
    if (CE && ExprHasName(CE, "netdev_priv", C)) {
      if (CE->getNumArgs() >= 1) {
        const Expr *Arg0 = CE->getArg(0);
        const MemRegion *NetdevReg = getMemRegionFromExpr(Arg0, C);
        if (NetdevReg) {
          NetdevReg = NetdevReg->getBaseRegion();
          State = State->set<PtrToNetdev>(LHSReg, NetdevReg);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // Case B: Propagate aliasing: LHS = RHS and RHS already mapped to a net_device
  const MemRegion *RHSReg = getRHSRegionFromBind(Val);
  if (RHSReg) {
    const MemRegion *OwnerNetdev = State->get<PtrToNetdev>(RHSReg);
    if (OwnerNetdev) {
      State = State->set<PtrToNetdev>(LHSReg, OwnerNetdev);
      C.addTransition(State);
      return;
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Mark free_netdev argument net_device as freed
  if (isCallTo(Call, "free_netdev", C)) {
    const MemRegion *NetdevReg = getArgRegion(Call, 0, C);
    if (NetdevReg) {
      State = State->set<NetdevFreedMap>(NetdevReg, 1);
      C.addTransition(State);
    }
    return;
  }

  // For all other calls, scan arguments for uses of private data (adpt->...)
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    const MemRegion *BasePtrReg = argContainsMemberBasePtrRegion(ArgE, C);
    if (!BasePtrReg)
      continue;

    const MemRegion *OwnerNetdev = getOwnerNetdevForPtr(State, BasePtrReg);
    if (!OwnerNetdev)
      continue;

    if (isNetdevFreed(State, OwnerNetdev)) {
      reportUAF(ArgE, OwnerNetdev, C);
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // We are interested in member accesses like adpt->... after free_netdev(netdev)
  const MemRegion *BasePtrReg = getMemberBasePtrRegion(S, C);
  if (!BasePtrReg)
    return;

  const MemRegion *OwnerNetdev = getOwnerNetdevForPtr(State, BasePtrReg);
  if (!OwnerNetdev)
    return;

  if (isNetdevFreed(State, OwnerNetdev)) {
    reportUAF(S, OwnerNetdev, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free of net_device private data after free_netdev()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
