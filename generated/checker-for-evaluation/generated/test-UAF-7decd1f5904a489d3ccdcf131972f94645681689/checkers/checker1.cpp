#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
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

// Register a program state map to track freed subflow memory regions.
// The map associates the base MemRegion with a boolean flag (true if freed).
REGISTER_MAP_WITH_PROGRAMSTATE(FreedSubflowMap, const MemRegion *, bool)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker 
  : public Checker< check::PostCall, // To intercept mptcp_close_ssk calls.
                    check::Location  // To detect loads of subflow->request_join.
                  > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Use-after-free", "Memory Error")) {}

  // Callback to track calls to mptcp_close_ssk.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to detect loads from freed subflow members.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report use-after-free bug.
  void reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // First, check if the call is to mptcp_close_ssk.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "mptcp_close_ssk", C))
    return;

  // We are expecting mptcp_close_ssk(sk, ssk, subflow)
  // Ensure there are at least 3 arguments.
  if (Call.getNumArgs() < 3)
    return;

  // Retrieve the subflow pointer argument (third parameter, index 2).
  SVal SubflowVal = Call.getArgSVal(2);
  const MemRegion *MR = SubflowVal.getAsRegion();
  if (!MR)
    return;

  // Get the base region.
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark the subflow region as freed.
  ProgramStateRef State = C.getState();
  State = State->set<FreedSubflowMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only inspect load operations.
  if (!IsLoad || !S)
    return;

  // Check if the statement is a member expression.
  const MemberExpr *ME = dyn_cast<MemberExpr>(S);
  if (!ME)
    return;

  // Use the utility function to check whether this member access is for "request_join".
  if (!ExprHasName(ME, "request_join", C))
    return;

  // Retrieve the base subflow pointer from which the member is accessed.
  const Expr *BaseExpr = ME->getBase();
  if (!BaseExpr)
    return;
    
  // Do not call IgnoreImplicit() per suggestions.
  const MemRegion *BaseMR = getMemRegionFromExpr(BaseExpr, C);
  if (!BaseMR)
    return;
  BaseMR = BaseMR->getBaseRegion();
  if (!BaseMR)
    return;

  // Query the program state to see if this subflow region has been freed.
  ProgramStateRef State = C.getState();
  const bool *Freed = State->get<FreedSubflowMap>(BaseMR);
  if (Freed && *Freed) {
    reportUseAfterFree(BaseMR, S, C);
  }
}

void SAGenTestChecker::reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use-after-free: accessing freed subflow->request_join", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use-after-free: reading member 'request_join' of a freed subflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
