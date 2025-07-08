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

// Additional includes
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states
REGISTER_MAP_WITH_PROGRAMSTATE(TaintedAllocMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// This checker detects cases where memory allocated using a device-managed
/// function (devm_kcalloc) is later manually freed using
/// pinctrl_utils_free_map, which leads to a potential double free.
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> { 
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Double free of devm_* allocated memory")) {}

  // Callback for tracking device-managed allocations
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback for detecting manual free operations that use tainted allocations
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback for tracking pointer aliasing (optional but recommended)
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to report a diagnostic when a double free is detected.
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                          const MemRegion *MR) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Check if the call is to devm_kcalloc.
  // Using ExprHasName for accurate checking.
  if (!ExprHasName(OriginExpr, "devm_kcalloc", C))
    return;
  
  // Retrieve the return value's memory region.
  const MemRegion *MR = Call.getReturnValue().getAsRegion();
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Mark the region as "tainted" (i.e., allocated via devm_kcalloc).
  State = State->set<TaintedAllocMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Check if the function being called is a manual free, for example,
  // pinctrl_utils_free_map.
  if (!ExprHasName(OriginExpr, "pinctrl_utils_free_map", C))
    return;
  
  // Assume the pointer to be freed is the first argument.
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Check if the memory region has been flagged as allocated by devm_kcalloc.
  const bool *Tainted = State->get<TaintedAllocMap>(MR);
  if (Tainted && *Tainted) {
    reportDoubleFree(Call, C, MR);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // Use pointer aliasing to track assignments between pointers.
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (!RHSReg)
        return;
      State = State->set<PtrAliasMap>(LHSReg, RHSReg);
      State = State->set<PtrAliasMap>(RHSReg, LHSReg);
    }
  }
  
  C.addTransition(State);
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                                          const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free: memory allocated via devm_kcalloc is freed manually", N);
  // Add source range for clarity.
  if (const Expr *OriginExpr = Call.getOriginExpr()) {
    report->addRange(OriginExpr->getSourceRange());
  }
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects double free of devm_kcalloc allocated memory via manual free calls", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
