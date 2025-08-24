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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/Lex/Lexer.h"
#include "clang/AST/ParentMapContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state customization: track the latest "late activation step" result variable and resource.
REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToResMap, const MemRegion*, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToStepKindMap, const MemRegion*, unsigned)

namespace {

static constexpr unsigned LateActivationStep = 1;

// Helper: strip to the canonical base region (VarRegion/ParmVarRegion/SymbolicRegion)
static const MemRegion *stripToBaseVarRegion(const MemRegion *R) {
  if (!R) return nullptr;
  const MemRegion *Base = R->getBaseRegion();
  return Base ? Base : R;
}

// Helper: check if two regions have the same base.
static bool sameBase(const MemRegion *A, const MemRegion *B) {
  if (!A || !B) return false;
  return stripToBaseVarRegion(A) == stripToBaseVarRegion(B);
}

// Helper: predicate for late activation step call names.
static bool isLateStepCallExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  // Use source text contains checks to be robust.
  // Minimal requirement: contains "set_" and ("_rdy" or "ready").
  // Also accept "activate", "enable", "arm".
  if (ExprHasName(E, "activate", C)) return true;
  if (ExprHasName(E, "enable", C)) return true;
  if (ExprHasName(E, "arm", C)) return true;
  if (ExprHasName(E, "set_", C) &&
      (ExprHasName(E, "_rdy", C) || ExprHasName(E, "ready", C)))
    return true;
  return false;
}

// Helper: predicate for high-level close/free/cleanup (not destroy)
static bool isHighLevelCloseCallExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  // Avoid proper destroy counterparts.
  if (ExprHasName(E, "destroy", C)) return false;
  if (ExprHasName(E, "close", C)) return true;
  if (ExprHasName(E, "cleanup", C)) return true;
  if (ExprHasName(E, "free", C)) return true;
  return false;
}

// Helper: pick a resource base region from a CallEvent (scan args from last to first).
static const MemRegion *pickResourceBaseRegionFromCall(const CallEvent &Call, CheckerContext &C) {
  for (unsigned i = Call.getNumArgs(); i > 0; --i) {
    unsigned Idx = i - 1;
    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE) continue;

    // Skip obvious device-like args to reduce noise.
    if (ExprHasName(ArgE, "mdev", C) || ExprHasName(ArgE, "dev", C))
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR) continue;
    MR = stripToBaseVarRegion(MR);
    if (MR) return MR;
  }
  return nullptr;
}

// Helper: extract error variable region from condition (e.g., if (err) { ... }).
static const MemRegion *getErrVarRegionFromCond(const Stmt *Cond, CheckerContext &C) {
  if (!Cond) return nullptr;
  const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Cond);
  if (!DRE) return nullptr;
  const Expr *E = DRE;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = stripToBaseVarRegion(MR);
  return MR;
}

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::Bind, check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free in error path", "Resource Management")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Identify and record "err = late_step_call(...)" and the associated resource.
      void recordLateStepAssignment(const MemRegion *ErrVarR, const CallExpr *CE, CheckerContext &C) const;

      // Reporting
      void reportIssue(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::recordLateStepAssignment(const MemRegion *ErrVarR, const CallExpr *CE, CheckerContext &C) const {
  if (!ErrVarR || !CE) return;

  // Verify it looks like a "late activation step" call.
  if (!isLateStepCallExpr(CE, C)) return;

  // Heuristically pick the resource base from the call's args (scan from last).
  const MemRegion *ResBase = nullptr;
  for (unsigned i = CE->getNumArgs(); i > 0; --i) {
    const Expr *ArgE = CE->getArg(i - 1);
    if (!ArgE) continue;

    // Skip common device params.
    if (ExprHasName(ArgE, "mdev", C) || ExprHasName(ArgE, "dev", C))
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR) continue;
    MR = stripToBaseVarRegion(MR);
    if (MR) { ResBase = MR; break; }
  }
  if (!ResBase) return;

  ProgramStateRef State = C.getState();
  State = State->set<ErrVarToResMap>(ErrVarR, ResBase);
  State = State->set<ErrVarToStepKindMap>(ErrVarR, LateActivationStep);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  // We are looking for patterns like: err = set_*_rdy(...);
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) return;
  LHSReg = stripToBaseVarRegion(LHSReg);
  if (!LHSReg) return;

  // Only consider top-level variable/parameter bindings.
  if (!(isa<VarRegion>(LHSReg) || isa<ParmVarRegion>(LHSReg)))
    return;

  // Try to find a CallExpr within this statement.
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE) return;

  recordLateStepAssignment(LHSReg, CE, C);
}

void SAGenTestChecker::reportIssue(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "High-level close/free on late-step failure may double free; call destroy_* instead.",
      N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return;

  // We only care about high-level close/free/cleanup (but not destroy).
  if (!isHighLevelCloseCallExpr(Origin, C))
    return;

  // Determine the resource passed to this cleanup call.
  const MemRegion *CleanupRes = pickResourceBaseRegionFromCall(Call, C);
  if (!CleanupRes) return;

  // Find an enclosing if-statement for this call.
  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Origin, C);
  if (!If) return;

  // Extract the error variable used in condition: if (err) ...
  const MemRegion *ErrVarR = getErrVarRegionFromCond(If->getCond(), C);
  if (!ErrVarR) return;

  ProgramStateRef State = C.getState();
  const MemRegion *const *TrackedResPtr = State->get<ErrVarToResMap>(ErrVarR);
  const unsigned *Step = State->get<ErrVarToStepKindMap>(ErrVarR);

  if (!TrackedResPtr || !Step) return;
  if (*Step != LateActivationStep) return;

  const MemRegion *TrackedRes = *TrackedResPtr;

  // Ensure that the resource matches.
  if (!sameBase(TrackedRes, CleanupRes)) return;

  // All matched: report.
  reportIssue(Call, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect mismatched high-level cleanup on late-step failure that may cause double free; suggest destroy_* instead",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
