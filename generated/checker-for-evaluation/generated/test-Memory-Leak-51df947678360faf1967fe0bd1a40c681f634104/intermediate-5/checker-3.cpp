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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map that maps net_device regions to a flag indicating
// whether they are allocated (true) or freed (false).
REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedNetdevMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall,   // To track allocations via alloc_etherdev.
                     check::PreCall,    // To track deallocations via free_netdev.
                     check::EndFunction // To check at function exit.
                    > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Resource Leak",
                                        "Resource Management")) {}

  // Callback to track functions that allocate resources.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to track functions that free resources.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback invoked at function exit.
  // We check for error exit in rvu_rep_create and report any leaked net_device.
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helper to report resource leak bug.
  void reportLeak(const MemRegion *MR, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Check for allocation function: alloc_etherdev
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "alloc_etherdev", C))
    return;

  ProgramStateRef State = C.getState();
  // Retrieve the allocated pointer as a memory region.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  // Mark this net_device as allocated (true).
  State = State->set<AllocatedNetdevMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Check for free function: free_netdev
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "free_netdev", C))
    return;

  ProgramStateRef State = C.getState();
  // free_netdev takes the pointer as its first argument.
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  // Mark the net_device as freed by updating its allocated flag to false.
  State = State->set<AllocatedNetdevMap>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Retrieve the current function declaration.
  const StackFrameContext *SFC = C.getPredecessor()->getLocationContext()->getStackFrame();
  if (!SFC)
    return;
  const Decl *D = SFC->getDecl();
  if (!D)
    return;
  // Only check for the rvu_rep_create function.
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
    if (FD->getName() != "rvu_rep_create")
      return;
  } else {
    return;
  }

  // Check if the return value indicates an error.
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;
  llvm::APSInt Result;
  if (!EvaluateExprToInt(Result, RetE, C))
    return;
  // If return value is non-constant or non-negative, we do not report.
  if (!Result.isSigned() || Result >= 0)
    return;

  // Retrieve the map entries for AllocatedNetdevMap and iterate over them.
  auto AllocMap = State->get<AllocatedNetdevMap>();
  for (auto I = AllocMap.begin(), E = AllocMap.end(); I != E; ++I) {
    const MemRegion *Reg = I->first;
    bool Allocated = I->second;
    if (Allocated) {
      reportLeak(Reg, C);
    }
  }
}

void SAGenTestChecker::reportLeak(const MemRegion *MR, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "net_device resource leak: allocated netdev not freed on error exit", N);
  // Removed the unsupported call to 'addVisitorFocus'. The bug report now uses the basic information.
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects failure to free an allocated net_device resource on error exit in rvu_rep_create", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
