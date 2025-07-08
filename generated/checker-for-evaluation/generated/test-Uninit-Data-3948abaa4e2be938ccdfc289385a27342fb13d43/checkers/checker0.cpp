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

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track the initialization flag of allocated memory regions.
// true  => memory is uninitialized (allocated via kmalloc)
// false => memory is initialized (allocated via kzalloc)
REGISTER_MAP_WITH_PROGRAMSTATE(UninitMemoryMap, const MemRegion *, bool)

// (Optionally) you can add a pointer aliasing map if needed in the future.
// REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
  : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Kernel Info Leak", "Kernel Memory Safety")) {}

  // Callback to track memory allocation functions (kmalloc/kzalloc).
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback to intercept calls to copy_to_user.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Optional: track pointer aliasing if needed
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Reporting routine for uninitialized memory copied to user.
  void reportUninitMemoryLeak(const MemRegion *MR, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
    
  // Check for kmalloc allocation.
  if (ExprHasName(OriginExpr, "kmalloc", C)) {
    const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Mark this allocated memory as uninitialized.
    State = State->set<UninitMemoryMap>(MR, true);
    C.addTransition(State);
  }
  // Check for kzalloc allocation.
  else if (ExprHasName(OriginExpr, "kzalloc", C)) {
    const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Mark this allocated memory as initialized.
    State = State->set<UninitMemoryMap>(MR, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Check for copy_to_user call.
  if (ExprHasName(OriginExpr, "copy_to_user", C)) {
    // For copy_to_user the kernel memory source is the second argument (index 1).
    if (Call.getNumArgs() < 2)
      return;
    SVal KernelPtrVal = Call.getArgSVal(1);
    const MemRegion *MR = KernelPtrVal.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Retrieve the flag for this memory allocation.
    const bool *UninitFlag = State->get<UninitMemoryMap>(MR);
    if (UninitFlag && *UninitFlag) {
      // Uninitialized memory is being copied to user space.
      reportUninitMemoryLeak(MR, C);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Optionally, update aliasing information if pointer copies occur.
  // For this checker we do not propagate the uninit flag to aliases.
  // In a more comprehensive checker, you could retrieve the memory regions from Loc and Val,
  // and update a PtrAliasMap accordingly.
  C.addTransition(C.getState());
}

void SAGenTestChecker::reportUninitMemoryLeak(const MemRegion *MR, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Uninitialized kmalloced memory copied to user", N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of kmalloc allocated memory that is uninitialized and then copied to user space", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
