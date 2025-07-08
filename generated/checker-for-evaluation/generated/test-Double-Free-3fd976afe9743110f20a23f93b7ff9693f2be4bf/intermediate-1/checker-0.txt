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

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track memory regions allocated via devm_* functions.
REGISTER_MAP_WITH_PROGRAMSTATE(DevmAllocMap, const MemRegion*, bool)
// Register a map to track pointer aliasing (optional for deeper alias analysis).
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Double Free on Device-Managed Memory")) {}

  // Callback to track device-managed allocations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback to detect manual free on device-managed memory.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback to track pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report the double free bug.
  void reportDoubleFree(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Intercept calls to the device-managed allocation function: devm_kcalloc.
  if (!ExprHasName(OriginExpr, "devm_kcalloc", C))
    return;

  // Retrieve the MemRegion corresponding to the return value.
  SVal RetVal = Call.getReturnValue();
  const MemRegion *MR = RetVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark this region as allocated by a devm_* function.
  State = State->set<DevmAllocMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Intercept calls to the manual free function.
  // In our target buggy code, pinctrl_utils_free_map is used to free the map.
  if (!ExprHasName(OriginExpr, "pinctrl_utils_free_map", C))
    return;

  // Retrieve the pointer argument that is being freed.
  // Assume the pointer is provided as the first argument (index 0).
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Check if this MemRegion was allocated using devm_kcalloc.
  bool IsDevm = false;
  if (const bool *DevmFlag = State->get<DevmAllocMap>(MR))
    IsDevm = *DevmFlag;

  if (IsDevm) {
    reportDoubleFree(MR, Call, C);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSRegion = Loc.getAsRegion();
  if (!LHSRegion)
    return;
  LHSRegion = LHSRegion->getBaseRegion();
  if (!LHSRegion)
    return;
  const MemRegion *RHSRegion = Val.getAsRegion();
  if (!RHSRegion)
    return;
  RHSRegion = RHSRegion->getBaseRegion();
  if (!RHSRegion)
    return;

  // Update pointer aliasing mapping: record that LHS and RHS reference the same memory.
  State = State->set<PtrAliasMap>(LHSRegion, RHSRegion);
  State = State->set<PtrAliasMap>(RHSRegion, LHSRegion);
  C.addTransition(State);
}

void SAGenTestChecker::reportDoubleFree(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free on device-managed memory", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects double free when memory allocated with devm_kcalloc is manually freed via pinctrl_utils_free_map",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
