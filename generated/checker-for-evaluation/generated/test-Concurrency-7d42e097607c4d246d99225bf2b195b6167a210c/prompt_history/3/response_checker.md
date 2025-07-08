```cpp
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

// Register a program state map to keep track for each reset_data allocation
// whether its completion has been checked by a call to completion_done().
REGISTER_MAP_WITH_PROGRAMSTATE(CompletionCheckedMap, const MemRegion*, bool)
// Program state map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Helper that, given a MemRegion from a subfield (e.g. the 'compl' field),
/// returns the container region (i.e. reset_data region). For many memory
/// regions, getBaseRegion() returns the whole object.
static const MemRegion *getContainerRegion(const MemRegion *MR) {
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

class SAGenTestChecker
    : public Checker< check::PreCall, check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Race condition", "Use-after-free")) {}

  // Callback for function call events.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback for pointer binding events.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;

private:
  // Report a bug: reset_data freed without a prior completion check.
  void reportMissingCompletion(const CallEvent &Call, CheckerContext &C,
                               const MemRegion *ResetReg) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use ExprHasName for precise checking.

  // 1) When completion_done is called, mark the containing reset_data as checked.
  if (ExprHasName(OriginExpr, "completion_done", C)) {
    // We assume the first argument (index 0) is the completion pointer.
    SVal ArgVal = Call.getArgSVal(0);
    const MemRegion *ComplMR = ArgVal.getAsRegion();
    if (!ComplMR)
      return;
    const MemRegion *ResetReg = getContainerRegion(ComplMR);
    if (!ResetReg)
      return;
    // Mark as checked in our program state.
    State = State->set<CompletionCheckedMap>(ResetReg, true);
    C.addTransition(State);
    return;
  }

  // 2) When kfree is called, verify if the reset_data pointer is freed after
  // a completion_done() check.
  if (ExprHasName(OriginExpr, "kfree", C)) {
    SVal ArgVal = Call.getArgSVal(0);
    const MemRegion *FreeMR = ArgVal.getAsRegion();
    if (!FreeMR)
      return;
    const MemRegion *ResetReg = getContainerRegion(FreeMR);
    if (!ResetReg)
      return;

    // Check if the completion has been marked as done.
    const bool *Checked = State->get<CompletionCheckedMap>(ResetReg);
    if (!Checked || *Checked == false) {
      reportMissingCompletion(Call, C, ResetReg);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // When a pointer is assigned, update the alias mapping.
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
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::reportMissingCompletion(const CallEvent &Call,
                                                 CheckerContext &C,
                                                 const MemRegion *ResetReg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Race condition: reset_data freed without completion check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects race condition in reset_data free: kfree called without prior completion_done check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```