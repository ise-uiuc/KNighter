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

// Register a program state map to track whether an object has been anchored
REGISTER_MAP_WITH_PROGRAMSTATE(AnchorMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
      : BT(new BugType(this, "UAF: Publishing Unanchored Object")) {}
  
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
private:
  void reportUAF(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // Process call to xe_file_get: mark the returned MemRegion as anchored.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use utility function ExprHasName for reliable checking.
  if (ExprHasName(OriginExpr, "xe_file_get", C)) {
    // Get the return value's memory region.
    const MemRegion *RetMR = Call.getReturnValue().getAsRegion();
    if (RetMR) {
      RetMR = RetMR->getBaseRegion();
      if (RetMR) {
        State = State->set<AnchorMap>(RetMR, true);
        C.addTransition(State);
      }
    }
    return;
  }
  
  // Process call to xa_alloc: check that the object being published has been anchored.
  if (OriginExpr && ExprHasName(OriginExpr, "xa_alloc", C)) {
    // In the call to xa_alloc, the third argument (index 2) is the object being published.
    if (Call.getNumArgs() <= 2)
      return; // Not enough arguments.
    
    SVal ObjVal = Call.getArgSVal(2);
    const MemRegion *ObjMR = ObjVal.getAsRegion();
    if (!ObjMR)
      return;
    
    ObjMR = ObjMR->getBaseRegion();
    if (!ObjMR)
      return;
    
    // Check if this object has been anchored.
    const bool *Anchored = State->get<AnchorMap>(ObjMR);
    if (!Anchored || !(*Anchored)) {
      // Bug found: The object's id is being published via xa_alloc before anchoring.
      reportUAF(ObjMR, Call, C);
    }
  }
}

void SAGenTestChecker::reportUAF(const MemRegion *MR, const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential UAF: Unique id published before proper anchoring", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects when an object's unique id is published before it is properly anchored (via xe_file_get)", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
