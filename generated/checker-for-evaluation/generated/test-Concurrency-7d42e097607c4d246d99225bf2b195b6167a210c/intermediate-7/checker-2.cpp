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

// Additional includes if necessary
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include <memory>  // for std::unique_ptr

using namespace clang;
using namespace ento;
using namespace taint;

// Register program state maps to track freed reset_data and pointer aliasing.
// ResetDataFreedMap tracks whether a reset_data region has been freed.
REGISTER_MAP_WITH_PROGRAMSTATE(ResetDataFreedMap, const MemRegion*, bool)
// PtrAliasMap tracks aliasing relationships for reset_data pointers.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Helper to check if the given expression (after stripping casts
/// and parentheses) is a reference to an entity whose name contains
/// the given substring.
static bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const ValueDecl *VD = DRE->getDecl())
      // Check if the name of the referenced variable/function contains the substring.
      return VD->getName().contains(Name);
  }
  return false;
}

/// Helper to obtain the memory region corresponding to an expression.
/// It obtains the SVal from the state and then returns its region (if any).
static const MemRegion *getMemRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenCasts();
  SVal Val = C.getState()->getSVal(E, C.getLocationContext());
  return Val.getAsRegion();
}

class SAGenTestChecker : public Checker<check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Double free of reset_data")) {}

  // Callback to intercept calls.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback to track pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper function to propagate the freed flag to all aliases.
  ProgramStateRef propagateFreed(ProgramStateRef State, const MemRegion *Reg) const {
    // Check if there is an alias.
    if (const MemRegion *const *AliasPtr = State->get<PtrAliasMap>(Reg)) {
      const MemRegion *Alias = *AliasPtr;
      State = State->set<ResetDataFreedMap>(Alias, true);
    }
    return State;
  }
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Only intercept calls to "kfree"
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use ExprHasName to check if the origin expression contains "kfree".
  if (!Call.isGlobalCFunction() ||
      !ExprHasName(OriginExpr, "kfree", C))
    return;

  // Make sure callee's name is indeed "kfree"
  const IdentifierInfo *CalleeId = Call.getCalleeIdentifier();
  if (!CalleeId || StringRef(CalleeId->getName()) != "kfree")
    return;

  // Get the first argument of kfree.
  if (Call.getNumArgs() < 1)
    return;
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (!MR)
    return;
    
  // Get the base region, which is what we track.
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Use the helper function ExprHasName() to limit to reset_data pointers.
  if (!ExprHasName(Call.getArgExpr(0), "reset_data", C))
    return;

  // Check if this region has already been freed.
  const bool *FreedFlag = State->get<ResetDataFreedMap>(MR);
  if (FreedFlag && *FreedFlag == true) {
    // Double free detected.
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Double free of reset_data detected", ErrNode);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
    return;
  }
  
  // Mark the reset_data object as freed.
  State = State->set<ResetDataFreedMap>(MR, true);
  // Propagate the freed flag via any alias that we have tracked.
  State = propagateFreed(State, MR);
  
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // Only record pointer aliasing if the bound value seems to be a reset_data.
  if (!StoreE)
    return;
  
  // Check if the source statement text contains "reset_data"
  if (!ExprHasName(dyn_cast<Expr>(StoreE), "reset_data", C))
    return;
  
  const MemRegion *LHSReg = Loc.getAsRegion();
  const MemRegion *RHSReg = Val.getAsRegion();
  if (!LHSReg || !RHSReg)
    return;
  
  // Get the base regions.
  LHSReg = LHSReg->getBaseRegion();
  RHSReg = RHSReg->getBaseRegion();
  if (!LHSReg || !RHSReg)
    return;
  
  // Set up aliasing relationships.
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of reset_data due to race condition in freeing paths", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
