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

using namespace clang;
using namespace ento;
using namespace taint;

// Track serdev devices whose client ops have been set.
REGISTER_SET_WITH_PROGRAMSTATE(SerdevOpsSet, const MemRegion *)
// Track serdev devices we already reported on this path to avoid duplicates.
REGISTER_SET_WITH_PROGRAMSTATE(SerdevReported, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Serdev open before ops", "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper to fetch the base MemRegion from a call argument expression.
  const MemRegion *getBaseRegionFromArg(const CallEvent &Call, unsigned Idx,
                                        CheckerContext &C) const {
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
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Mark ops as set for the given serdev device.
  if (!ExprHasName(Origin, "serdev_device_set_client_ops", C))
    return;

  const MemRegion *SerdevMR = getBaseRegionFromArg(Call, 0, C);
  if (!SerdevMR)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<SerdevOpsSet>(SerdevMR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  bool IsDevmOpen = ExprHasName(Origin, "devm_serdev_device_open", C);
  bool IsOpen = ExprHasName(Origin, "serdev_device_open", C);
  if (!IsDevmOpen && !IsOpen)
    return;

  unsigned SerdevIdx = IsDevmOpen ? 1u : 0u;
  const MemRegion *SerdevMR = getBaseRegionFromArg(Call, SerdevIdx, C);
  if (!SerdevMR)
    return;

  ProgramStateRef State = C.getState();
  // If ops are already set, everything is fine.
  if (State->contains<SerdevOpsSet>(SerdevMR))
    return;

  // Avoid duplicate reports on the same path.
  if (State->contains<SerdevReported>(SerdevMR))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  // Tailor the message to the specific open function used.
  StringRef OpenName = IsDevmOpen ? "devm_serdev_device_open()" : "serdev_device_open()";
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, (OpenName + " called before serdev_device_set_client_ops(); callbacks may deref NULL ops").str(), N);

  // Highlight the call site.
  R->addRange(Origin->getSourceRange());
  C.emitReport(std::move(R));

  // Mark as reported to avoid duplicates and transition the state.
  State = State->add<SerdevReported>(SerdevMR);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects serdev ports opened before client ops are set, which may cause NULL ops dereference",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
