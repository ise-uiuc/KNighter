#include "clang/AST/Expr.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
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

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track initialization status of objects.
// True means that the object's critical member (xef) has been set.
REGISTER_MAP_WITH_PROGRAMSTATE(InitStatusMap, const MemRegion *, bool)

// (Optional) Register a program state map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Partial Initialization Published", 
                         "Use-After-Free Prevention")) {}

  // Callback to process function calls after evaluation.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback to track binding assignments.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Report a bug when an object is published before fully initializing the critical member.
  void reportPartialInit(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const;
  
  // Helper to mark the object's region as fully initialized.
  ProgramStateRef markInitialized(ProgramStateRef State, const MemRegion *MR) const;
};

ProgramStateRef SAGenTestChecker::markInitialized(ProgramStateRef State, const MemRegion *MR) const {
  if (!MR)
    return State;
    
  MR = MR->getBaseRegion();
  // Mark the region as initialized (true).
  State = State->set<InitStatusMap>(MR, true);
  
  // Propagate to any alias if available.
  if (const MemRegion * const *AliasP = State->get<PtrAliasMap>(MR)) {
    const MemRegion *Alias = *AliasP;
    State = State->set<InitStatusMap>(Alias, true);
  }
  
  return State;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // Attempt to see if the left-hand side of a binding (assignment) sets the critical member "xef".
  // We use ExprHasName to check if the source text of the LHS contains "->xef" or ".xef".
  // Do not call IgnoreImplicit() before getMemRegionFromExpr.
  if (!StoreE)
    return;
  
  // Check if the store expression (the left-hand side) references the critical member.
  if (ExprHasName(cast<Expr>(StoreE), "->xef", C) || ExprHasName(cast<Expr>(StoreE), ".xef", C)) {
    // Retrieve the memory region for the left-hand side.
    const MemRegion *MR = getMemRegionFromExpr(cast<Expr>(StoreE), C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    
    ProgramStateRef State = C.getState();
    State = markInitialized(State, MR);
    C.addTransition(State);
  }
  
  // (Optional) Handle pointer aliasing: if the left-hand side is a pointer and is assigned a value from another pointer.
  // Record the aliasing information.
  const MemRegion *LHSReg = getMemRegionFromExpr(cast<Expr>(StoreE), C);
  if (LHSReg) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;
    const MemRegion *RHSReg = getMemRegionFromExpr(cast<Expr>(StoreE), C);
    if (RHSReg) {
      RHSReg = RHSReg->getBaseRegion();
      ProgramStateRef State = C.getState();
      State = State->set<PtrAliasMap>(LHSReg, RHSReg);
      State = State->set<PtrAliasMap>(RHSReg, LHSReg);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept calls to xa_alloc.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "xa_alloc", C))
    return;

  // We assume that the object pointer is passed as the third argument (index 2).
  if (Call.getNumArgs() < 3)
    return;
  
  SVal ObjectArgVal = Call.getArgSVal(2);
  const MemRegion *MR = ObjectArgVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  ProgramStateRef State = C.getState();
  const bool *Init = State->get<InitStatusMap>(MR);
  // If initialization status is not set to true, then the object is published prematurely.
  if (!Init || !(*Init)) {
    reportPartialInit(MR, Call, C);
  }
}

void SAGenTestChecker::reportPartialInit(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Object published via xa_alloc before critical member (xef) fully initialized", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects publication of partially-initialized object (critical member xef not set) via xa_alloc",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
