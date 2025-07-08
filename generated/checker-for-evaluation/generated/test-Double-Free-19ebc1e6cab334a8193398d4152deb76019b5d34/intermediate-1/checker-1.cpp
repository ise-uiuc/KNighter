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
#include "clang/Lex/Lexer.h"  // for getSourceText (if needed)

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state:
// FreedPtrMap maps a memory region (with its base) to a boolean indicating if it was freed.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedPtrMap, const MemRegion*, bool)
// Optionally we can track pointer aliasing, but here we only update FreedPtrMap in checkBind.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::Bind > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Double free detected")) {}

  // Callback for function call events.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback for binding events (pointer assignments).
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // (Optional) A helper to update aliasing information for a pointer.
  ProgramStateRef updateAliasesToNotFreed(ProgramStateRef State, const MemRegion *MR) const;
};

ProgramStateRef SAGenTestChecker::updateAliasesToNotFreed(ProgramStateRef State, const MemRegion *MR) const {
  // If there is an alias recorded, mark it as not freed as well.
  if (const MemRegion *const *AliasMRPtr = State->get<PtrAliasMap>(MR)) {
    const MemRegion *AliasMR = *AliasMRPtr;
    State = State->set<FreedPtrMap>(AliasMR, false);
  }
  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // We are interested in functions called "kfree" only.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "kfree", C))
    return;

  // kfree should have at least one argument.
  if (Call.getNumArgs() < 1)
    return;

  SVal Arg = Call.getArgSVal(0);
  const MemRegion *MR = Arg.getAsRegion();
  if (!MR)
    return;

  // Get the base region.
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *FreedFlag = State->get<FreedPtrMap>(MR);
  if (FreedFlag && *FreedFlag) {
    // This region has already been freed, report a double free.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "Double free detected", N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  } else {
    // Mark this pointer's memory region as freed.
    State = State->set<FreedPtrMap>(MR, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // When binding, we are interested in pointer variables.
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;

    // If the RHS is a null constant then it reinitializes the pointer.
    if (Val.isZeroConstant()) {
      // Mark the region as not freed.
      State = State->set<FreedPtrMap>(LHSReg, false);
      // Update any pointer alias as well.
      State = updateAliasesToNotFreed(State, LHSReg);
      C.addTransition(State);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects double free due to not reinitializing a pointer after free", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
