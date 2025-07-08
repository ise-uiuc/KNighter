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

// Add any additional includes if needed

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states.
// Register a map to track freed subflow memory regions.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedMemoryMap, const MemRegion*, bool)
// Register a pointer alias map for tracking alias relationships.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Location, check::Bind> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Use-After-Free on subflow field")) {}

  // Callback declarations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Self-defined helper function to report use-after-free error.
  void reportUAF(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Use the utility function ExprHasName to verify the function name.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "mptcp_close_ssk", C))
    return;

  // mptcp_close_ssk is expected to free subflow memory.
  // In the call, the subflow pointer is passed as the third argument, index 2.
  if (Call.getNumArgs() < 3)
    return;

  SVal SubflowVal = Call.getArgSVal(2);
  const MemRegion *MR = SubflowVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark the subflow region as freed.
  State = State->set<FreedMemoryMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // We're interested in loads accessing a field named "request_join"
  // Ensure this is a load access.
  if (!IsLoad || !S)
    return;

  // If the statement is a MemberExpr then check if the field name is "request_join".
  const MemberExpr *ME = dyn_cast<MemberExpr>(S);
  if (!ME)
    return;

  // Use utility function to check if the source text contains "request_join".
  if (!ExprHasName(ME, "request_join", C))
    return;

  // Get the base of the member access expression (e.g. the subflow pointer).
  const Expr *BaseExpr = ME->getBase();
  if (!BaseExpr)
    return;

  const MemRegion *BaseMR = getMemRegionFromExpr(BaseExpr, C);
  if (!BaseMR)
    return;
  BaseMR = BaseMR->getBaseRegion();
  if (!BaseMR)
    return;

  ProgramStateRef State = C.getState();
  const bool *FreedFlag = State->get<FreedMemoryMap>(BaseMR);
  if (FreedFlag && *FreedFlag) {
    // Report use-after-free: a field ("request_join") is being accessed on a subflow that has been freed.
    reportUAF(BaseMR, S, C);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Handle pointer aliasing by tracking relationships.
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

  // Record alias: when a subflow pointer is stored into another, record this relationship.
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportUAF(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "UAF: Access of freed subflow field 'request_join'", ErrNode);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free: accessing a subflow field after mptcp_close_ssk frees it",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
