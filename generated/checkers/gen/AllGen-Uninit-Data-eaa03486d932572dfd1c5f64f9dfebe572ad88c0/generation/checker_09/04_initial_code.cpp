#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to track whether a local "status" variable has been initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(StatusVarInitMap, const VarDecl *, bool)

namespace {

class SAGenTestChecker
    : public Checker<
          check::PostStmt<DeclStmt>, // Seed tracking on local declarations
          check::Bind,               // Mark as initialized on assignments
          check::PreStmt<ReturnStmt> // Warn on returning uninitialized var
          > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Uninitialized status return", "Logic error")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  static bool shouldTrackVar(const VarDecl *VD);
};

bool SAGenTestChecker::shouldTrackVar(const VarDecl *VD) {
  if (!VD)
    return false;

  // Only track automatic local non-static variables.
  if (!VD->hasLocalStorage() || VD->isStaticLocal())
    return false;

  QualType T = VD->getType();
  // Restrict to integer-like scalar "status" candidates.
  if (!(T->isIntegerType() || T->isEnumeralType() || T->isBooleanType()))
    return false;

  return true;
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!shouldTrackVar(VD))
      continue;

    // Initialize tracking: true if it has an initializer, otherwise false.
    bool IsInitialized = VD->hasInit();
    State = State->set<StatusVarInitMap>(VD, IsInitialized);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt * /*S*/,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const auto *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return;

  // If we are tracking this variable, mark it as initialized on this path.
  if (State->contains<StatusVarInitMap>(VD)) {
    State = State->set<StatusVarInitMap>(VD, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  RetE = RetE->IgnoreParenImpCasts();

  const auto *DRE = dyn_cast<DeclRefExpr>(RetE);
  if (!DRE)
    return;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  // Only consider tracked variables.
  ProgramStateRef State = C.getState();
  const bool *IsInit = State->get<StatusVarInitMap>(VD);
  if (!IsInit)
    return;

  if (!*IsInit) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    std::string VarName = VD->getNameAsString();
    if (VarName.empty())
      VarName = "<status>";

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Returning uninitialized status variable '" + VarName + "'.", N);
    Report->addRange(RetE->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects returning an uninitialized local status variable (e.g., 'int ret;')",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
