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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track local integer-like "ret" variables without initializer.
REGISTER_SET_WITH_PROGRAMSTATE(TrackedRetVars, const VarDecl *)
// Track which of the above have been assigned on the current path.
REGISTER_SET_WITH_PROGRAMSTATE(InitRetVars, const VarDecl *)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Uninitialized return status", "Logic")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  static bool isIntegerLike(QualType QT) {
    QT = QT.getCanonicalType();
    return QT->isIntegerType() || QT->isEnumeralType();
  }
};
} // end anonymous namespace

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    // Only consider local, non-parameter variables named exactly "ret".
    if (!VD->hasLocalStorage() || isa<ParmVarDecl>(VD))
      continue;

    if (VD->getName() != "ret")
      continue;

    // Integer-like and no initializer.
    if (VD->hasInit())
      continue;

    if (!isIntegerLike(VD->getType()))
      continue;

    // Track this variable as a candidate status variable.
    if (!State->contains<TrackedRetVars>(VD)) {
      State = State->add<TrackedRetVars>(VD);
    }
    // Do not mark as initialized here; absence from InitRetVars means "not yet assigned".
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt * /*S*/, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // The bind target is the location being written to.
  if (const MemRegion *MR = Loc.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *VR = dyn_cast<VarRegion>(MR)) {
      const VarDecl *VD = VR->getDecl();
      if (VD && State->contains<TrackedRetVars>(VD)) {
        // Mark this variable as initialized on this path.
        if (!State->contains<InitRetVars>(VD)) {
          State = State->add<InitRetVars>(VD);
        }
      }
    }
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD)
    return;

  // Only report for integer-like function return types.
  if (!isIntegerLike(FD->getReturnType()))
    return;

  const Expr *E = RS->getRetValue();
  if (!E)
    return;

  E = E->IgnoreImpCasts();

  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  // Must be a tracked "ret" and not yet initialized on this path.
  ProgramStateRef State = C.getState();
  if (!State->contains<TrackedRetVars>(VD))
    return;

  if (State->contains<InitRetVars>(VD))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Returning uninitialized status variable 'ret' (initialize to 0).", N);
  R->addRange(RS->getSourceRange());
  // Optional note at declaration site.
  R->addNote("'ret' declared here without an initializer", VD->getLocation());
  C.emitReport(std::move(R));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect returning uninitialized local 'ret' status variable",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
