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

// Additional includes.
#include "clang/Lex/Lexer.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customized program state maps.
// FreedPointerMap: tracks pointer members (i.e. bdev_file) that are freed but not nullified.
// PtrAliasMap: tracks pointer aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedPointerMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker< check::PreCall,  // intercept free-function calls (e.g. fput)
                    check::Bind,     // catch assignments (e.g. pointer = NULL)
                    check::Location> // catch pointer usage (potential UAF)
{
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Use-after-free due to missing nullification")) {}

  // Callback: Intercept free function calls.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: Intercept pointer assignments.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Callback: Intercept pointer usage/dereference.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to report bug for using a pointer that was freed and not nullified.
  void reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // We intercept free functions such as "fput".
  // Use the utility function "ExprHasName" on the call's origin to check if it is "fput".
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin || !ExprHasName(Origin, "fput", C))
    return;

  // For fput, the first argument is the pointer that is freed.
  if (Call.getNumArgs() < 1)
    return;

  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;

  // Get the base region.
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // To reduce false positives, check if the free is being applied to a "bdev_file".
  // We use ExprHasName on Origin to look for "bdev_file" in the source text.
  if (!ExprHasName(Origin, "bdev_file", C))
    return;

  // Mark the pointer as freed (and not yet nullified).
  State = State->set<FreedPointerMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Get the left-hand-side (LHS) memory region.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // For aliasing tracking: if the RHS is another pointer, record the alias.
  if (const MemRegion *RHSReg = Val.getAsRegion()) {
    RHSReg = RHSReg->getBaseRegion();
    if (RHSReg) {
      State = State->set<PtrAliasMap>(LHSReg, RHSReg);
      State = State->set<PtrAliasMap>(RHSReg, LHSReg);
    }
  }

  // Check if the value being bound is a null pointer.
  // The SVal interface provides isZeroConstant() to check for a null constant.
  if (Val.isZeroConstant()) {
    // Optionally, restrict the update to pointer assignments for "bdev_file".
    // Use the source text of the assignment (StoreE) to decide.
    if (StoreE && ExprHasName(cast<Expr>(StoreE), "bdev_file", C)) {
      // Mark the pointer as nullified (i.e. not freed anymore).
      State = State->set<FreedPointerMap>(LHSReg, false);

      // Also update its alias if any.
      if (auto AliasRegPtr = State->get<PtrAliasMap>(LHSReg)) {
        const MemRegion *AliasReg = *AliasRegPtr;
        State = State->set<FreedPointerMap>(AliasReg, false);
      }
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // We are only interested in pointer usage when dereferencing (load) operations.
  if (!IsLoad)
    return;
  
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Check our FreedPointerMap to see if this pointer was previously freed but not nullified.
  const bool *FreedFlag = State->get<FreedPointerMap>(MR);
  if (FreedFlag && *FreedFlag) {
    // Report a bug: the pointer (bdev_file) is being used after free without nullification.
    reportUseAfterFree(MR, S, C);
  }
}

void SAGenTestChecker::reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  // Emit a short and clear bug report.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Pointer not nullified after free", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use-after-free when a pointer is not nullified after its resource is freed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
