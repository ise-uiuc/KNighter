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
#include "clang/AST/Stmt.h"
// Replace the non-existent header with the correct one:
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states:
// Map from VarDecl* to a bool indicating whether the variable has been initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(VarInitializationMap, const VarDecl*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostStmt, check::Bind, check::PreStmt> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Uninitialized return value", "Uninitialized Variable")) {}

  // Callback for processing declaration statements.
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  
  // Callback for processing assignments (bindings).
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  
  // Callback for processing return statement before it is executed.
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helper function: Report uninitialized return of variable 'ret'
  void reportUninitReturn(const ReturnStmt *RS, CheckerContext &C) const;
};

/// checkPostStmt - Process declaration statements to record uninitialized "ret".
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Iterate over all declarations in the DeclStmt.
  for (const auto *D : DS->decls()) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
      // Check if the variable name is "ret" and it is of integer type.
      if (VD->getName() == "ret" && VD->getType()->isIntegerType()) {
        // If there is no initializer, mark it as uninitialized.
        bool isInit = VD->hasInit();
        State = State->set<VarInitializationMap>(VD, isInit);
      }
    }
  }
  C.addTransition(State);
}

/// checkBind - Update the initialized status if "ret" is assigned.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // Retrieve the memory region for the left-hand side.
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Check if the region corresponds to a variable.
  if (const VarRegion *VR = dyn_cast<VarRegion>(MR)) {
    const VarDecl *VD = VR->getDecl();
    if (VD && VD->getName() == "ret" && VD->getType()->isIntegerType()) {
      // An assignment to "ret" has occurred. Mark it as initialized.
      State = State->set<VarInitializationMap>(VD, true);
      C.addTransition(State);
    }
  }
}

/// checkPreStmt - Check return statements to catch uninitialized "ret".
void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *retExpr = RS->getRetValue();
  if (!retExpr)
    return;
  
  // Remove implicit casts and parens.
  retExpr = retExpr->IgnoreParenImpCasts();
  
  // If the return expression is a DeclRefExpr, check if it refers to "ret".
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(retExpr)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (VD->getName() == "ret" && VD->getType()->isIntegerType()) {
        const bool *isInit = State->get<VarInitializationMap>(VD);
        if (isInit && !(*isInit)) {
          reportUninitReturn(RS, C);
        }
      }
    }
  }
}

/// reportUninitReturn - Report a bug for returning an uninitialized "ret".
void SAGenTestChecker::reportUninitReturn(const ReturnStmt *RS, CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;
  
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Returning uninitialized variable 'ret'", ErrNode);
  Report->addRange(RS->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects the use of an uninitialized local variable 'ret' as the function return value",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
