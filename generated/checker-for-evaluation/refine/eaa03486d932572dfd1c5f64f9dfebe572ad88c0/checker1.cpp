// /scratch/chenyuan-data/SAGEN/result-0224-bugfail-multi-o3mini/test-Uninit-Data-eaa03486d932572dfd1c5f64f9dfebe572ad88c0/checkers/checker4.cpp
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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to keep track of the initialization status of a variable 'ret'.
// The mapping: VarDecl* -> bool (true means initialized, false means uninitialized).
REGISTER_MAP_WITH_PROGRAMSTATE(UninitVarMap, const VarDecl*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                          check::Bind,
                                          check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Uninitialized Variable", "Uninitialized ret usage")) {}

  // Called after a declaration statement is processed.
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;

  // Called when a value is bound to a variable.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

  // Called before a return statement is processed.
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
};

// checkPostStmt: Processes declaration statements to record "ret" variables
// that are declared without an initializer.
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
      if (VD->getName() == "ret") {
        // If 'ret' has no initializer, mark it as uninitialized.
        if (!VD->hasInit()) {
          State = State->set<UninitVarMap>(VD, false);
        }
      }
    }
  }
  C.addTransition(State);
}

// checkBind: Processes bindings (assignments) to update the initialization status
// of a variable. If a binding to the "ret" variable occurs, mark it as initialized.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Try to extract the variable from the left-hand side of the binding.
  if (const Expr *E = dyn_cast<Expr>(S)) {
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->getName() == "ret") {
          // Mark the variable as having been initialized.
          State = State->set<UninitVarMap>(VD, true);
          C.addTransition(State);
          return;
        }
      }
    }
  }
  C.addTransition(State);
}

// checkPreStmt: Called before a ReturnStmt is processed.
// If the return expression is a direct use of the variable "ret" and it is still uninitialized,
// report a bug.
void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *retExpr = RS->getRetValue();
  if (!retExpr)
    return;

  retExpr = retExpr->IgnoreImplicit();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(retExpr)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (VD->getName() == "ret") {
        const bool *Initialized = State->get<UninitVarMap>(VD);
        if (Initialized && !(*Initialized)) {
          ExplodedNode *N = C.generateNonFatalErrorNode();
          if (!N)
            return;
          auto report = std::make_unique<PathSensitiveBugReport>(
              *BT, "Uninitialized variable 'ret' used", N);
          report->addRange(retExpr->getSourceRange());
          C.emitReport(std::move(report));
        }
      }
    }
  }
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects usage of uninitialized local variable 'ret'", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
