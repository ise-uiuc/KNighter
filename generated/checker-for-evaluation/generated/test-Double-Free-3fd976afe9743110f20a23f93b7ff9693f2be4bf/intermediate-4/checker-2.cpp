#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states
// Map to track memory regions allocated via devm_kcalloc.
// The boolean value is true if the region was allocated by devm_kcalloc.
REGISTER_MAP_WITH_PROGRAMSTATE(DeviceManagedAllocMap, const MemRegion *, bool)
// Map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Double free of device-managed allocation")) {}

  // Callback to track automatic allocations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to check for manual free calls.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to track pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report double free.
  void reportDoubleFree(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Check if this is a call to devm_kcalloc.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Use ExprHasName to verify function call name.
  if (!ExprHasName(OriginExpr, "devm_kcalloc", C))
    return;
  
  ProgramStateRef State = C.getState();

  // Retrieve the memory region associated with the returned value.
  // Do not call IgnoreImplicit() as per instructions.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Mark this region as allocated by devm_kcalloc.
  State = State->set<DeviceManagedAllocMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // We want to intercept manual free calls.
  // Check for the free function "pinctrl_utils_free_map". 
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "pinctrl_utils_free_map", C))
    return;

  ProgramStateRef State = C.getState();
  
  // For pinctrl_utils_free_map, assume pointer is passed as the first argument.
  if (Call.getNumArgs() < 1)
    return;

  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Follow aliasing if necessary.
  if (auto AliasPtr = State->get<PtrAliasMap>(MR)) {
    if (const MemRegion *Alias = *AliasPtr)
      MR = Alias->getBaseRegion();
  }

  // Check in our DeviceManagedAllocMap: if the region was allocated by devm_kcalloc,
  // then manual free is a double free.
  const bool *IsDeviceManaged = State->get<DeviceManagedAllocMap>(MR);
  if (IsDeviceManaged && *IsDeviceManaged) {
    reportDoubleFree(MR, Call, C);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If the left-hand side is a pointer and the right-hand side is a pointer,
  // record aliasing.
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

  // Record the aliasing relationship in both directions.
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportDoubleFree(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  // Use the PathSensitiveBugReport constructor which accepts an ExplodedNode.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free of device-managed allocation detected", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects a double free bug when devm_kcalloc allocated memory "
      "is manually freed via pinctrl_utils_free_map", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
