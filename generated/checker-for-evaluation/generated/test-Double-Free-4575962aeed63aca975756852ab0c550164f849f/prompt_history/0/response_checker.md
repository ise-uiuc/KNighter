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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states:
// DeviceManagedMap: tracks memory allocated with a devm_* function. True indicates the
// memory was allocated through device-managed routines.
REGISTER_MAP_WITH_PROGRAMSTATE(DeviceManagedMap, const MemRegion*, bool)
// PtrAliasMap: tracks aliasing between MemRegions.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::PreCall, check::Bind> {
  
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Double free: Manual free on devm allocated memory")) {}

  // Callback declarations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  
private:
  // Report a bug if a free-call is attempted on device managed memory.
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Check for devm allocation function: devm_kcalloc.
  if (ExprHasName(OriginExpr, "devm_kcalloc", C)) {
    // Get the allocated memory's region.
    const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
    if (!MR)
      return;
    
    MR = MR->getBaseRegion();
    // Mark this region as device managed.
    State = State->set<DeviceManagedMap>(MR, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Look for manual free functions, here: pinctrl_utils_free_map.
  if (ExprHasName(OriginExpr, "pinctrl_utils_free_map", C)) {
    // pinctrl_utils_free_map's second parameter is the memory pointer that is freed.
    if (Call.getNumArgs() < 2)
      return;
    
    SVal ArgVal = Call.getArgSVal(1);
    const MemRegion *MR = ArgVal.getAsRegion();
    if (!MR)
      return;
    
    MR = MR->getBaseRegion();
    // Check if the memory region was allocated via devm_*.
    const bool *isDeviceManaged = State->get<DeviceManagedMap>(MR);
    if (isDeviceManaged && *isDeviceManaged) {
      // Report a bug if a device managed region is manually freed.
      reportDoubleFree(Call, C, MR);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // Propagate pointer aliasing information.
  ProgramStateRef State = C.getState();
  const MemRegion *LHS = Loc.getAsRegion();
  const MemRegion *RHS = Val.getAsRegion();
  if (!LHS || !RHS)
    return;
  
  LHS = LHS->getBaseRegion();
  RHS = RHS->getBaseRegion();
  if (!LHS || !RHS)
    return;
  
  State = State->set<PtrAliasMap>(LHS, RHS);
  State = State->set<PtrAliasMap>(RHS, LHS);
  
  // Propagate the device-managed flag from the RHS to LHS if present.
  const bool *RHSFlag = State->get<DeviceManagedMap>(RHS);
  if (RHSFlag && *RHSFlag) {
    State = State->set<DeviceManagedMap>(LHS, true);
  }
  C.addTransition(State);
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                                          const MemRegion *MR) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free: Manual free on devm allocated memory", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects double free: Manual free on memory allocated via device-managed allocators", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```