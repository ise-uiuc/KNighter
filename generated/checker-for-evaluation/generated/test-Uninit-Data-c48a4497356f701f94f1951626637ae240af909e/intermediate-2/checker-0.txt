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

// Customize program states
REGISTER_MAP_WITH_PROGRAMSTATE(FwStateMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::PreCall, check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked request_firmware usage")) {}

  // Callback for function call after evaluation.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback for function call before evaluation.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to propagate pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // (Optional) Additional helper functions can be declared here.
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // We target the call to request_firmware.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use utility function to check the function name.
  if (!ExprHasName(OriginExpr, "request_firmware", C))
    return;
  
  // Ensure that there is an out-parameter.
  if (Call.getNumArgs() < 1)
    return;
  
  // Retrieve the first argument (the out parameter where the firmware pointer is stored).
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;
  
  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return;
  
  // Always work with the base region.
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  ProgramStateRef State = C.getState();
  // Mark the firmware pointer as unchecked (false).
  State = State->set<FwStateMap>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // We target the call to release_firmware.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  if (!ExprHasName(OriginExpr, "release_firmware", C))
    return;
  
  // Ensure that release_firmware has at least one argument.
  if (Call.getNumArgs() < 1)
    return;
  
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<FwStateMap>(MR);
  
  // If the firmware pointer was recorded as unchecked then report a bug.
  if (Unchecked && (*Unchecked == false)) {
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Unchecked request_firmware: firmware pointer uninitialized", ErrNode);
    Report->addRange(Arg0->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // Get the left-hand side memory region.
  const MemRegion *LHSMR = Loc.getAsRegion();
  if (!LHSMR)
    return;
  LHSMR = LHSMR->getBaseRegion();
  if (!LHSMR)
    return;
  
  // Get the right-hand side memory region.
  const MemRegion *RHSMR = Val.getAsRegion();
  if (!RHSMR)
    return;
  RHSMR = RHSMR->getBaseRegion();
  if (!RHSMR)
    return;
  
  // If the RHS is recorded in FwStateMap, propagate its status to the LHS.
  const bool *Status = State->get<FwStateMap>(RHSMR);
  if (Status) {
    State = State->set<FwStateMap>(LHSMR, *Status);
    // Optionally record the aliasing for future propagation.
    State = State->set<PtrAliasMap>(LHSMR, RHSMR);
    State = State->set<PtrAliasMap>(RHSMR, LHSMR);
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unchecked firmware pointer from request_firmware being used in release_firmware",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
