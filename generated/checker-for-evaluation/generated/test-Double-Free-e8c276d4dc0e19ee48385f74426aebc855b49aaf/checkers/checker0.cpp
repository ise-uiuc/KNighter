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

// Add your includes here
#include "clang/AST/Expr.h"
#include "clang/AST/ASTContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states
REGISTER_MAP_WITH_PROGRAMSTATE(FreedMemMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::PreCall, check::Bind> { 
   mutable std::unique_ptr<BugType> BT;
   
public:
   SAGenTestChecker() : BT(new BugType(this, "Double free of fastrpc buf")) {}

   // Declaration of Callback Functions
   void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
   void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
   void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
   
private:
   // Declaration of Self-defined Functions
   void reportDoubleFree(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const;
};

//
// In checkPostCall we intercept calls to fastrpc_req_munmap_impl and mark the associated
// 'buf' memory region as freed in our FreedMemMap.
//
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Make sure this is a call to fastrpc_req_munmap_impl.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "fastrpc_req_munmap_impl", C))
    return;
  
  // The second parameter of fastrpc_req_munmap_impl is the buffer (index 1).
  if (Call.getNumArgs() < 2)
    return;
  
  SVal ArgVal = Call.getArgSVal(1);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<FreedMemMap>(MR, true);
  C.addTransition(State);
}

//
// In checkPreCall we intercept calls to fastrpc_buf_free.  We retrieve the memory region 
// of the buffer passed (first parameter) and then check our FreedMemMap. If it has already 
// been freed, we report a double free bug. Otherwise, we mark it as freed.
//
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "fastrpc_buf_free", C))
    return;
  
  if (Call.getNumArgs() < 1)
    return;
  
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Freed = State->get<FreedMemMap>(MR);
  if (Freed && *Freed) {
    reportDoubleFree(Call, C, MR);
    return;
  }
  
  // Mark the region as freed for this free operation.
  State = State->set<FreedMemMap>(MR, true);
  C.addTransition(State);
}

//
// In checkBind we track pointer aliasing.
// When one pointer is assigned to another, we update the PtrAliasMap so that if one of the aliases is marked freed,
// the information can be propagated to its alias.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;
    
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (!RHSReg)
        return;
      
      State = State->set<PtrAliasMap>(LHSReg, RHSReg);
      State = State->set<PtrAliasMap>(RHSReg, LHSReg);
    }
  }
  
  C.addTransition(State);
}

//
// Helper function that generates a bug report for double free detection.
void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free of fastrpc buf", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects error-path cleanup issues where the same fastrpc buffer is freed twice",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
