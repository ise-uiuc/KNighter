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
#include "clang/AST/Expr.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track whether a pointer (i.e. device->bdev_file)
// has been freed (true means freed but not reset to NULL).
REGISTER_MAP_WITH_PROGRAMSTATE(FreeStateMap, const MemRegion*, bool)
// Optionally track alias relationships for pointer values.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::Bind, check::Location > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Use-after-free due to non-NULL reset")) {}

  // Callback when a function call returns.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback for assignments (tracking pointer assignments).
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  // Callback for pointer dereferences and location uses.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper: report error when a freed pointer is used.
  void reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
  
  // Helper: check whether an expression appears to be the "bdev_file" field.
  bool isBdevFileExpr(const Expr *E, CheckerContext &C) const {
    if (!E)
      return false;
    return ExprHasName(E, "bdev_file", C);
  }
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Check if the called function is "fput"
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use utility function to check the callee function name accurately.
  if (!ExprHasName(OriginExpr, "fput", C))
    return;

  // We are interested in calls freeing bdev_file. Check the argument expression.
  if (Call.getNumArgs() < 1)
    return;
  
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  // We want to ensure this fput call is applied on device->bdev_file.
  if (!isBdevFileExpr(ArgExpr, C))
    return;
  
  // Get the MemRegion for the argument.
  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;
    
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Mark the region as freed but not nulled.
  State = State->set<FreeStateMap>(MR, true);
  C.addTransition(State);

  // In case there is aliasing information, mark aliases too.
  if (const auto *AliasPtr = State->get<PtrAliasMap>(MR)) {
    const MemRegion *Alias = *AliasPtr;
    State = State->set<FreeStateMap>(Alias, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If the left-hand side is not a region, bail out.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // Check if the left-hand side is the device->bdev_file field by inspecting the source.
  const Expr *LHSExpr = nullptr;
  if (StoreE) {
    if (const Expr *E = dyn_cast<Expr>(StoreE))
      LHSExpr = E->IgnoreImplicit();
  }
  if (!LHSExpr)
    return;
  if (!isBdevFileExpr(LHSExpr, C))
    return;

  // Now check if the right-hand side is setting the pointer to NULL.
  llvm::APSInt Eval;
  if (Val.getAs<DefinedOrUnknownSVal>()) {
    // Try to evaluate the RHS expression.
    const Expr *RHSExpr = nullptr;
    if (StoreE) {
      if (const Expr *E = dyn_cast<Expr>(StoreE))
        RHSExpr = E->IgnoreImplicit();
    }
    if (RHSExpr && EvaluateExprToInt(Eval, RHSExpr, C)) {
      if (Eval == 0) {
        // Pointer is being set to NULL; remove the entry from FreeStateMap.
        State = State->remove<FreeStateMap>(LHSReg);
        // Clear any alias mapping as well.
        if (State->get<PtrAliasMap>(LHSReg))
          State = State->remove<PtrAliasMap>(LHSReg);
        C.addTransition(State);
        return;
      }
    }
  }

  // Additionally, track pointer aliasing.
  if (const MemRegion *RHSReg = Val.getAsRegion()) {
    RHSReg = RHSReg->getBaseRegion();
    if (!RHSReg)
      return;
    State = State->set<PtrAliasMap>(LHSReg, RHSReg);
    State = State->set<PtrAliasMap>(RHSReg, LHSReg);
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

  // Check if this region is marked as freed but not nulled.
  const bool *Freed = State->get<FreeStateMap>(MR);
  if (Freed && *Freed) {
    reportUseAfterFree(MR, S, C);
  }
}

void SAGenTestChecker::reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use-after-free: device->bdev_file freed via fput but not reset to NULL", N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use-after-free due to device->bdev_file not being reset to NULL after free", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
