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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track out-params (e.g., 'fw') passed to request_firmware() when the return
// value is ignored. We map the variable's MemRegion to a boolean marker.
REGISTER_MAP_WITH_PROGRAMSTATE(OutParamNeedingRetCheck, const MemRegion*, bool)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Uninitialized firmware pointer use", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool isRequestFirmware(const CallEvent &Call, CheckerContext &C);
      static bool isReleaseFirmware(const CallEvent &Call, CheckerContext &C);
      static bool isCallResultIgnored(const CallEvent &Call, CheckerContext &C);

      static const MemRegion *getOutParamRegionFromArg0(const CallEvent &Call, CheckerContext &C);
      static const MemRegion *getVarRegionFromDeclRefExpr(const Expr *E, CheckerContext &C);

      void reportUse(const MemRegion *MR, CheckerContext &C, const Stmt *S) const;
      void reportRelease(const MemRegion *MR, CheckerContext &C, const CallEvent &Call) const;
};

// Check function name via source text for accuracy.
bool SAGenTestChecker::isRequestFirmware(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "request_firmware", C);
}

bool SAGenTestChecker::isReleaseFirmware(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "release_firmware", C);
}

// Determine if the return value of the call is ignored (bare statement).
bool SAGenTestChecker::isCallResultIgnored(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // If the call is directly used in a condition, assignment, declaration
  // (with initializer), or return, we consider it not ignored.
  if (findSpecificTypeInParents<IfStmt>(Origin, C))
    return false;

  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(Origin, C)) {
    if (BO->isAssignmentOp())
      return false;
  }

  if (findSpecificTypeInParents<DeclStmt>(Origin, C))
    return false;

  if (findSpecificTypeInParents<ReturnStmt>(Origin, C))
    return false;

  return true;
}

// Get the MemRegion of the out-parameter (variable region) from arg0 (&fw).
const MemRegion *SAGenTestChecker::getOutParamRegionFromArg0(const CallEvent &Call, CheckerContext &C) {
  // First try via the SVal of the first argument, which should be &fw (address of the variable).
  SVal Arg0 = Call.getArgSVal(0);
  if (const MemRegion *R = Arg0.getAsRegion()) {
    R = R->getBaseRegion();
    if (R)
      return R;
  }

  // Fallback: find a DeclRefExpr inside arg0 and get its variable region.
  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return nullptr;
  const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(ArgE);
  if (!DRE)
    return nullptr;

  return getVarRegionFromDeclRefExpr(DRE, C);
}

// Obtain the VarRegion corresponding to a DeclRefExpr of a variable.
const MemRegion *SAGenTestChecker::getVarRegionFromDeclRefExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts());
  if (!DRE)
    return nullptr;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  SVal LV = C.getSValBuilder().getLValue(VD, C.getLocationContext());
  const MemRegion *MR = LV.getAsRegion();
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

// After calling request_firmware(&fw, ...), if the return is ignored,
// mark 'fw' as requiring a return-code check before use.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isRequestFirmware(Call, C))
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *OutR = getOutParamRegionFromArg0(Call, C);
  if (!OutR)
    return;

  if (isCallResultIgnored(Call, C)) {
    State = State->set<OutParamNeedingRetCheck>(OutR, true);
    C.addTransition(State);
  }
}

// Before calling release_firmware(fw), report if 'fw' came from a
// request_firmware() whose return was ignored.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isReleaseFirmware(Call, C))
    return;

  ProgramStateRef State = C.getState();

  const Expr *Arg0E = Call.getArgExpr(0);
  if (!Arg0E)
    return;

  const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Arg0E);
  const MemRegion *VarR = nullptr;
  if (DRE)
    VarR = getVarRegionFromDeclRefExpr(DRE, C);

  if (!VarR)
    return;

  VarR = VarR->getBaseRegion();
  const bool *Marked = State->get<OutParamNeedingRetCheck>(VarR);
  if (Marked && *Marked) {
    reportRelease(VarR, C, Call);
    // Erase to avoid duplicate reports along this path.
    State = State->remove<OutParamNeedingRetCheck>(VarR);
    C.addTransition(State);
  }
}

// When the firmware out-param variable is read (e.g., if (!fw)),
// report if the earlier request_firmware() return was ignored.
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad)
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  ProgramStateRef State = C.getState();
  const bool *Marked = State->get<OutParamNeedingRetCheck>(R);
  if (Marked && *Marked) {
    reportUse(R, C, S);
    State = State->remove<OutParamNeedingRetCheck>(R);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportUse(const MemRegion *MR, CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "request_firmware() return ignored; using firmware out-parameter", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportRelease(const MemRegion *MR, CheckerContext &C, const CallEvent &Call) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "request_firmware() return ignored; releasing uninitialized firmware pointer", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects ignoring request_firmware return and using/releasing the out-parameter",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
