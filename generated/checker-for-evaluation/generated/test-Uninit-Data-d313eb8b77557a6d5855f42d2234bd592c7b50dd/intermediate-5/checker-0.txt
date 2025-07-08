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
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states:
// Register a map to track if a memory region (e.g. a "tc_skbmod" structure)
// has been properly initialized (zeroed).
REGISTER_MAP_WITH_PROGRAMSTATE(InitMap, const MemRegion *, bool)

// Optionally register a pointer aliasing map (if needed).
// REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
    : public Checker< check::PostCall,  // To intercept memset calls.
                      check::PreCall,   // To intercept user-copy functions.
                      check::Bind > {   // To track pointer aliasing (optional).
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Uninitialized structure used for user copy")) {}

  // Callback invoked after function calls are evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback invoked before function calls are evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Optional: Track aliasing between pointers.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Report a potential bug: copying an uninitialized structure to user space.
  void reportKernelInfoLeak(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const;
};

//
// checkPostCall: Look for memset calls that initialize the structure.
// We are interested in calls to memset that clear a structure that is later copied.
// In our target patch, the patch adds a call to memset(&opt, 0, sizeof(opt));
// We use the utility function ExprHasName to see if the argument text includes "opt".
//
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if this is a call to memset.
  if (!ExprHasName(OriginExpr, "memset", C))
    return;

  // Make sure there is at least one argument.
  if (Call.getNumArgs() < 1)
    return;

  // We are interested in the pointer argument that is the destination.
  const Expr *DestExpr = dyn_cast<Expr>(Call.getArgExpr(0));
  if (!DestExpr)
    return;

  // If the source text of this expression contains "opt", then we assume
  // it refers to the structure "tc_skbmod" in our bug pattern.
  if (!ExprHasName(DestExpr, "opt", C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(DestExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark the region as initialized.
  State = State->set<InitMap>(MR, true);
  C.addTransition(State);
}

//
// checkPreCall: Look for calls that copy data to user space (e.g. nla_put, nla_put_64bit).
// We check the argument corresponding to the source data: if it comes from a structure that has
// not been zero-initialized, then we report a potential kernel infoleak bug.
//
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Intercept calls to functions known to copy data to user space.
  // For our bug pattern, we look for "nla_put" and "nla_put_64bit".
  if (!(ExprHasName(OriginExpr, "nla_put", C) || ExprHasName(OriginExpr, "nla_put_64bit", C)))
    return;

  // For both functions, the source data pointer is expected as
  // the 4th argument (index 3). Verify the argument count.
  if (Call.getNumArgs() < 4)
    return;

  const Expr *DataExpr = dyn_cast<Expr>(Call.getArgExpr(3));
  if (!DataExpr)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(DataExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Query the state: if our map does not indicate the region as initialized
  // (either not present or marked false), then emit a report.
  const bool *isInitialized = State->get<InitMap>(MR);
  if (!isInitialized || *isInitialized == false) {
    reportKernelInfoLeak(MR, Call, C);
  }
}

//
// checkBind: (Optional) Record pointer aliasing so that if a pointer variable is assigned from
// another one, their initialization states can be tracked together. For simplicity, here we
// update the state for the bound location if the value originates from a region already tracked.
//
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Get the memory region being bound on the left-hand side.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // Get the memory region from the value (right-hand side).
  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;

  // If the RHS region is tracked for initialization, propagate that to the LHS.
  const bool *rhsInit = State->get<InitMap>(RHSReg);
  if (rhsInit) {
    State = State->set<InitMap>(LHSReg, *rhsInit);
    C.addTransition(State);
  }
}

//
// reportKernelInfoLeak: Emits a non-fatal bug report about copying an uninitialized structure
// to user space.
//
void SAGenTestChecker::reportKernelInfoLeak(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential kernel information leak: structure with internal padding is not zero-initialized", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects copying of uninitialized (non-zeroed) structures that may leak kernel memory", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
