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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

//--------------------------------------------------
// 1. Customize Program States
//--------------------------------------------------
// Map to record memory regions allocated by devm_* functions.
// If a region is allocated with a devm_* allocator, we mark it as true.
REGISTER_MAP_WITH_PROGRAMSTATE(DevmTaintMap, const MemRegion *, bool)
// Optional: Map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Double free of devm_* allocated memory")) {}

  // 3. Implement checkPostCall Callback (Model the Allocation)
  // Intercept calls to devm_* allocators and mark their returned memory as tainted.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;
    // Check if the call is one of the devm_* allocators.
    if (ExprHasName(OriginExpr, "devm_kcalloc", C) ||
        ExprHasName(OriginExpr, "devm_kmalloc", C) ||
        ExprHasName(OriginExpr, "devm_kzalloc", C) ||
        ExprHasName(OriginExpr, "devm_kmalloc_array", C)) {
      // Retrieve the return value's memory region.
      const MemRegion *MR = Call.getReturnValue().getAsRegion();
      if (!MR)
        return;
      MR = MR->getBaseRegion();
      if (!MR)
        return;
      // Mark the memory region as tainted (i.e. auto-managed by devm_*).
      State = State->set<DevmTaintMap>(MR, true);
      C.addTransition(State);
    }
  }

  // 4. Implement checkPreCall Callback (Detecting Manual Deallocation)
  // Intercept calls to manual free functions like pinctrl_utils_free_map.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;
    // Look for calls to pinctrl_utils_free_map.
    if (!ExprHasName(OriginExpr, "pinctrl_utils_free_map", C))
      return;
    // Assume the pointer to free is the first argument.
    SVal ArgVal = Call.getArgSVal(0);
    const MemRegion *MR = ArgVal.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // If this memory region was allocated via devm_* (tainted), then it should not be freed manually.
    const bool *Tainted = State->get<DevmTaintMap>(MR);
    if (Tainted && *Tainted) {
      reportDoubleFree(MR, Call, C);
    }
  }

  // 5. (Optional) Track Pointer Aliases via checkBind
  // When a pointer value is stored into another variable, record aliasing information.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
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
    // Record the aliasing: if one pointer is tainted, its alias should also be considered tainted.
    State = State->set<PtrAliasMap>(LHSReg, RHSReg);
    State = State->set<PtrAliasMap>(RHSReg, LHSReg);
    C.addTransition(State);
  }

private:
  // Bug Reporting: Emit a warning when a tainted memory region from a devm_* alloc is manually freed.
  void reportDoubleFree(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Double free: devm_* allocated memory should not be manually freed", N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects double free vulnerabilities due to manual free of devm_* allocated memory", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
