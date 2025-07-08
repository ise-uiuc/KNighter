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
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states: Track netdev allocations.
// NetdevStateMap maps the allocated netdev region to a boolean flag:
// false = allocated (not freed), true = freed.
REGISTER_MAP_WITH_PROGRAMSTATE(NetdevStateMap, const MemRegion*, bool)
// PtrAliasMap tracks aliasing relationships between netdev pointer regions.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Missing cleanup in error handling")) {}

  // Callback declarations
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper: report bug when a netdev allocated by alloc_etherdev is not freed
  // in an error path following rvu_rep_devlink_port_register failure.
  void reportMissingCleanup(const MemRegion *NetdevRegion, CheckerContext &C) const;
};

//
// checkPostCall: Process calls for alloc_etherdev, free_netdev, and rvu_rep_devlink_port_register.
//
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // For function calls, use ExprHasName to perform precise matching.
  if (ExprHasName(OriginExpr, "alloc_etherdev", C)) {
    // Record the netdev pointer returned by alloc_etherdev.
    SVal RetVal = Call.getReturnValue();
    const MemRegion *MR = RetVal.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    // Mark this netdev pointer as allocated (false indicates not freed yet).
    State = State->set<NetdevStateMap>(MR, false);
    C.addTransition(State);
    return;
  }

  if (ExprHasName(OriginExpr, "free_netdev", C)) {
    // The free_netdev function frees netdev. Extract the argument, mark it as freed.
    if (Call.getNumArgs() < 1)
      return;
    SVal Arg0 = Call.getArgSVal(0);
    const MemRegion *MR = Arg0.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    // Mark the netdev pointer as freed.
    State = State->set<NetdevStateMap>(MR, true);
    C.addTransition(State);
    return;
  }

  if (ExprHasName(OriginExpr, "rvu_rep_devlink_port_register", C)) {
    // This function returns an error code. Check if it failed.
    llvm::APSInt ErrVal;
    if (!EvaluateExprToInt(ErrVal, OriginExpr, C))
      return;
    // If error is nonzero then we are in an error path.
    if (ErrVal != 0) {
      // Try to locate the netdev pointer allocated earlier for this iteration.
      // We look upward in the AST to find a DeclRefExpr named "ndev".
      const DeclRefExpr *DRE = findSpecificTypeInParents<DeclRefExpr>(OriginExpr, C);
      if (!DRE)
        return;
      if (!ExprHasName(DRE, "ndev", C))
        return;
      const MemRegion *MR = getMemRegionFromExpr(DRE, C);
      if (!MR)
        return;
      MR = MR->getBaseRegion();
      // Check our NetdevStateMap: If the netdev is still not freed, it is an error.
      const bool *Freed = State->get<NetdevStateMap>(MR);
      if (Freed && (*Freed == false)) {
        reportMissingCleanup(MR, C);
      }
    }
    C.addTransition(State);
    return;
  }
  
  // For any other calls, do nothing.
}

//
// checkBind: Record aliasing relationships between netdev pointers.
//
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // If the left-hand side (Loc) is a variable and the value Val is a region pointer,
  // then record alias information so that later free_netdev can mark it as freed.
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;
    if (const MemRegion *ValReg = Val.getAsRegion()) {
      ValReg = ValReg->getBaseRegion();
      if (!ValReg)
        return;
      // Record aliasing in both directions.
      State = State->set<PtrAliasMap>(LHSReg, ValReg);
      State = State->set<PtrAliasMap>(ValReg, LHSReg);
      C.addTransition(State);
    }
  }
}

//
// reportMissingCleanup: Emit a bug report for a netdev pointer that should have been freed.
//
void SAGenTestChecker::reportMissingCleanup(const MemRegion *NetdevRegion, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing free_netdev() call in error handling for allocated netdev", N);
  // Optionally add source range info if the region is a VarRegion.
  if (const auto *VR = dyn_cast_or_null<VarRegion>(NetdevRegion))
    Report->addRange(C.getSourceManager().getExpansionRange(VR->getDecl()->getLocation()));
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects missing free_netdev() call when rvu_rep_devlink_port_register() fails",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
  CLANG_ANALYZER_API_VERSION_STRING;
