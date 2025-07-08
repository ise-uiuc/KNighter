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
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: Track whether a subflow's memory region has been freed.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedSubflowMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::Location> {
  
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Use-after-free", "Subflow memory error")) {}
  
  // Callback: After a function call is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
  // Callback: On explicit memory load/store.
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const;
  
private:
  // Self-defined helper: Report use-after-free bug.
  void reportUAF(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Make sure we are looking at a call to mptcp_close_ssk.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "mptcp_close_ssk", C))
    return;
  
  // mptcp_close_ssk is expected to have at least 3 parameters:
  // (sk, ssk, subflow). We want to track the subflow parameter (index 2).
  if (Call.getNumArgs() < 3)
    return;
  
  // Retrieve the subflow expression (the third argument).
  const Expr *SubflowExpr = Call.getArgExpr(2);
  if (!SubflowExpr)
    return;
  
  const MemRegion *MR = getMemRegionFromExpr(SubflowExpr, C);
  if (!MR)
    return;
  
  // Get the base region.
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Mark the subflow's memory region as freed.
  ProgramStateRef State = C.getState();
  State = State->set<FreedSubflowMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;
  
  // Check if the current statement is a MemberExpr
  // and if its source code text contains the field "request_join".
  const MemberExpr *ME = dyn_cast<MemberExpr>(S);
  if (!ME)
    return;
  
  if (!ExprHasName(ME, "request_join", C))
    return;
  
  // Get the base expression of the member access.
  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return;
  
  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  ProgramStateRef State = C.getState();
  const bool *Freed = State->get<FreedSubflowMap>(MR);
  if (Freed && *Freed == true) {
    reportUAF(MR, S, C);
  }
}

void SAGenTestChecker::reportUAF(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use-after-free: subflow field 'request_join' accessed after free", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use-after-free on subflow field 'request_join' after mptcp_close_ssk may free the subflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
