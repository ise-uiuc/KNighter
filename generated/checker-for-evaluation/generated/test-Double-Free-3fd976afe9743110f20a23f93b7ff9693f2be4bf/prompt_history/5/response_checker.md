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
#include "clang/AST/Expr.h"  // For Expr

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: record pointers allocated via devm_* functions.
REGISTER_MAP_WITH_PROGRAMSTATE(TaintedPtrMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Double free of devm_* allocated memory")) {}

  // Called after a function call returns.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Called before a function call is executed.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the current program state.
  ProgramStateRef State = C.getState();

  // Get the origin expression of the call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if this call is to the device-managed allocation function devm_kcalloc.
  // We use the utility function to examine the source text.
  if (!ExprHasName(OriginExpr, "devm_kcalloc", C))
    return;

  // Retrieve the allocated memory’s region.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  
  // Always use the base region.
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark this memory region as allocated via a devm_* function.
  State = State->set<TaintedPtrMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Retrieve the current program state.
  ProgramStateRef State = C.getState();

  // Get the origin expression of the call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if the call is to the manual free function pinctrl_utils_free_map.
  if (!ExprHasName(OriginExpr, "pinctrl_utils_free_map", C))
    return;

  // Assume that the pointer being freed is passed as the first argument.
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Query our program state to see if this region was allocated by a devm_* function.
  const bool *IsDevm = State->get<TaintedPtrMap>(MR);
  if (IsDevm && *IsDevm) {
    // The free call is freeing memory that was automatically managed,
    // which indicates a potential double free.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Double free of devm_* allocated memory", N);
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects manual free of memory allocated by devm_* functions leading to double free", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```