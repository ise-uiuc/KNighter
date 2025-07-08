#include "clang/AST/Expr.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
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

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track if a pointer (the freed resource)
// has been freed (true) but not yet set to NULL.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedPtrMap, const MemRegion *, bool)
// Optionally, we can also track aliasing relationships using PtrAliasMap.
// REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Freed resource pointer not nullified")) {}

  // Called after a function call is executed.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Called when a value is bound to a location (e.g. assignment).
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Called on memory load/store operations.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to generate a bug report when a freed pointer is used.
  void reportFreedPtrUse(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Intercept calls to fput which free a resource.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Check using the utility function for accurate callee name matching.
  if (!ExprHasName(OriginExpr, "fput", C))
    return;

  // Get the pointer argument passed to fput (assume index 0).
  if (Call.getNumArgs() < 1)
    return;
  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark this region as freed.
  State = State->set<FreedPtrMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // We are interested in pointer assignments.
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  if (!LHS)
    return;

  // If the value being bound is a null constant, then the pointer is being nullified.
  if (Val.isZeroConstant()) {
    // Remove any freed flag for this pointer.
    State = State->remove<FreedPtrMap>(LHS);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Look up this memory region in our FreedPtrMap.
  const bool *IsFreed = State->get<FreedPtrMap>(MR);
  if (IsFreed && *IsFreed) {
    // If the region was freed but has not been nullified, report error.
    reportFreedPtrUse(MR, S, C);
  }
}

void SAGenTestChecker::reportFreedPtrUse(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freed resource pointer is used without being set to NULL", ErrNode);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use-after-free when a resource pointer is freed (via fput) but not nullified", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
