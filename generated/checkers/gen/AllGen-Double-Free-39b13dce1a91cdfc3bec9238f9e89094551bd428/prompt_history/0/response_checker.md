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
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state to map the return symbol of devm_add_action_or_reset()
// to its 'cleanup' function and 'data' pointer.
REGISTER_MAP_WITH_PROGRAMSTATE(DevmRetToCleanupFDMap, SymbolRef, const FunctionDecl*)
REGISTER_MAP_WITH_PROGRAMSTATE(DevmRetToDataRegionMap, SymbolRef, const MemRegion*)

// Program state to record that we are on the failure path (non-zero return)
// for a specific (data region -> cleanup function) pair.
REGISTER_MAP_WITH_PROGRAMSTATE(ActiveFailureMap, const MemRegion*, const FunctionDecl*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        eval::Assume> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Manual cleanup after devm_add_action_or_reset failure", "Linux kernel API misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

   private:
      static const FunctionDecl *getFunctionDeclFromExpr(const Expr *E);
      static bool isDevmAddActionOrReset(const CallEvent &Call, CheckerContext &C);
      void reportDoubleCleanup(const CallEvent &Call, CheckerContext &C) const;
};

const FunctionDecl *SAGenTestChecker::getFunctionDeclFromExpr(const Expr *E) {
  if (!E)
    return nullptr;

  const Expr *Cur = E->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
    if (UO->getOpcode() == UO_AddrOf)
      Cur = UO->getSubExpr()->IgnoreParenImpCasts();
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(Cur)) {
    return dyn_cast<FunctionDecl>(DRE->getDecl());
  }
  return nullptr;
}

bool SAGenTestChecker::isDevmAddActionOrReset(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Prefer source-text name check as suggested.
  return ExprHasName(Origin, "devm_add_action_or_reset", C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isDevmAddActionOrReset(Call, C))
    return;

  // Expect signature: int devm_add_action_or_reset(dev, cleanup, data)
  if (Call.getNumArgs() < 3)
    return;

  // Extract cleanup function decl from 2nd argument.
  const Expr *CleanupArg = Call.getArgExpr(1);
  const FunctionDecl *CleanupFD = getFunctionDeclFromExpr(CleanupArg);
  if (!CleanupFD)
    return;

  // Extract data pointer region from 3rd argument.
  const Expr *DataArg = Call.getArgExpr(2);
  const MemRegion *DataReg = getMemRegionFromExpr(DataArg, C);
  if (!DataReg)
    return;

  DataReg = DataReg->getBaseRegion();
  if (!DataReg)
    return;

  // Get the return symbol of the call.
  SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
  if (!RetSym)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<DevmRetToCleanupFDMap>(RetSym, CleanupFD);
  State = State->set<DevmRetToDataRegionMap>(RetSym, DataReg);
  C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  // We only care when the condition is exactly the return symbol of
  // devm_add_action_or_reset().
  SymbolRef Sym = Cond.getAsSymbol();
  if (!Sym)
    return State;

  const FunctionDecl *const *FDPtr = State->get<DevmRetToCleanupFDMap>(Sym);
  const MemRegion *const *MRPtr = State->get<DevmRetToDataRegionMap>(Sym);
  if (!FDPtr || !MRPtr)
    return State;

  const FunctionDecl *CleanupFD = *FDPtr;
  const MemRegion *DataReg = *MRPtr;

  // Erase the temporary mapping regardless of the branch to avoid stale entries.
  State = State->remove<DevmRetToCleanupFDMap>(Sym);
  State = State->remove<DevmRetToDataRegionMap>(Sym);

  // On non-zero (true) branch, devm_add_action_or_reset failed,
  // and it already invoked the cleanup(data).
  if (Assumption && CleanupFD && DataReg) {
    State = State->set<ActiveFailureMap>(DataReg, CleanupFD);
  }

  return State;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // We only handle direct calls to a function (i.e., we have a FunctionDecl).
  const Decl *D = Call.getDecl();
  const auto *CalleeFD = dyn_cast_or_null<FunctionDecl>(D);
  if (!CalleeFD)
    return;

  // We expect cleanup(void *data) - at least 1 arg is required.
  if (Call.getNumArgs() < 1)
    return;

  const Expr *DataArg = Call.getArgExpr(0);
  const MemRegion *ArgReg = getMemRegionFromExpr(DataArg, C);
  if (!ArgReg)
    return;

  ArgReg = ArgReg->getBaseRegion();
  if (!ArgReg)
    return;

  // Check if we are currently on a failure path for this (data -> cleanup) pair.
  const FunctionDecl *const *TrackedFD = State->get<ActiveFailureMap>(ArgReg);
  if (!TrackedFD || !*TrackedFD)
    return;

  if (*TrackedFD == CalleeFD) {
    reportDoubleCleanup(Call, C);
  }
}

void SAGenTestChecker::reportDoubleCleanup(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Manual cleanup after devm_add_action_or_reset() failure (double free)", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects manual cleanup after devm_add_action_or_reset() failure that leads to double free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
