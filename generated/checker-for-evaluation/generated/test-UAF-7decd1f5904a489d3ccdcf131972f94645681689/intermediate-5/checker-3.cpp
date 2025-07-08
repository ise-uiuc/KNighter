#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
// Removed Taint.h because it is not available in Clang-18.
// #include "clang/StaticAnalyzer/Checkers/Taint.h"
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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include <memory>

using namespace clang;
using namespace ento;

// Customize program states
REGISTER_MAP_WITH_PROGRAMSTATE(FreedSubflowMap, const MemRegion*, bool)
// Optional: Tracking pointer aliasing, if the subflow pointer is assigned to other variables.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::Location, check::Bind> 
{
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "UAF: Accessing freed subflow field", "Use-after-free")) {}

  // Callback for intercepting calls (used to mark subflow as freed).
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
  // Callback for intercepting loads/stores.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  
  // Callback for propagating alias information.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Optionally, a helper to emit bug reports.
  void reportUAF(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept calls to mptcp_close_ssk.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use the callee's name to check if it matches "mptcp_close_ssk".
  if (Call.getCalleeName() != "mptcp_close_ssk")
    return;

  // mptcp_close_ssk() is expected to be called with three arguments.
  // The subflow pointer is the third argument (index 2).
  if (Call.getNumArgs() < 3)
    return;
  
  const Expr *SubflowArg = Call.getArgExpr(2);
  if (!SubflowArg)
    return;
  
  const MemRegion *MR = getMemRegionFromExpr(SubflowArg, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  
  ProgramStateRef State = C.getState();
  State = State->set<FreedSubflowMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // We are interested in detecting accesses to the "request_join" field.
  // If S is a MemberExpr, then it might be an access to a field.
  const MemberExpr *ME = dyn_cast<MemberExpr>(S);
  if (!ME)
    return;

  // Check that the member field is named "request_join".
  const ValueDecl *MemberDecl = ME->getMemberDecl();
  if (!MemberDecl)
    return;
  if (MemberDecl->getNameAsString() != "request_join")
    return;

  // Retrieve the base object's memory region.
  const Expr *BaseExpr = ME->getBase();
  if (!BaseExpr)
    return;
  
  const MemRegion *BaseMR = getMemRegionFromExpr(BaseExpr, C);
  if (!BaseMR)
    return;
  BaseMR = BaseMR->getBaseRegion();

  // Check if the subflow region has been marked as freed.
  const bool *Freed = State->get<FreedSubflowMap>(BaseMR);
  if (Freed && *Freed) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "UAF: Accessing field request_join on a freed subflow", N);
    Report->addRange(S->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // If both the left-hand side and the right-hand side can be mapped to a memory region,
  // propagate the freed status by aliasing.
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  
  const MemRegion *RHS = Val.getAsRegion();
  if (!RHS)
    return;
  RHS = RHS->getBaseRegion();

  // Set alias relationship in PtrAliasMap.
  State = State->set<PtrAliasMap>(LHS, RHS);
  State = State->set<PtrAliasMap>(RHS, LHS);
  C.addTransition(State);
}

void SAGenTestChecker::reportUAF(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "UAF: Accessing field request_join on a freed subflow", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use-after-free: Accessing subflow->request_join after subflow was freed", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
