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

#include "clang/Lex/Lexer.h"  // For Lexer::getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: register a map to track devm_* allocated memory.
REGISTER_MAP_WITH_PROGRAMSTATE(TaintedMemMap, const MemRegion*, bool)
// Optionally, register a pointer alias map to propagate tainted status.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Double free of devm_* allocated memory")) {}

  // Callback to model auto-managed devm_* allocations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to report if a devm_* allocated pointer is freed manually.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to track pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // (Optional) self-defined helper to check tainted status from program state, 
  // including checking aliases.
  bool isTainted(ProgramStateRef State, const MemRegion *MR) const;
};

bool SAGenTestChecker::isTainted(ProgramStateRef State, const MemRegion *MR) const {
  if (!MR)
    return false;
  // First check MR directly.
  if (const bool *Flag = State->get<TaintedMemMap>(MR))
    if (*Flag)
      return true;
  // Next, check if there is an alias and if the alias is tainted.
  if (const MemRegion *Alias = State->get<PtrAliasMap>(MR)) {
    if (const bool *Flag = State->get<TaintedMemMap>(Alias))
      if (*Flag)
        return true;
  }
  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Use ExprHasName to check if the call is devm_kcalloc.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "devm_kcalloc", C))
    return;
  
  // Retrieve the memory region corresponding to the return value.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Mark the memory region as tainted.
  State = State->set<TaintedMemMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Check if the function is one that frees memory manually.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "pinctrl_utils_free_map", C))
    return;

  // Retrieve the pointer argument that is intended to be freed.
  // We assume it is the first argument.
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // If this region (or its alias) was allocated via devm_kcalloc, then it's tainted.
  if (isTainted(State, MR)) {
    // Generate a non-fatal error node and report the bug.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Double free: devm_* allocated memory should not be freed manually", N);
    report->addRange(Call.getSourceRange());
    C.emitReport(std::move(report));
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track pointer aliasing: if a pointer is assigned to another pointer,
  // record that they alias each other.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;
  
  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;

  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing of devm_* allocated memory (e.g. via devm_kcalloc) through manual free functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```