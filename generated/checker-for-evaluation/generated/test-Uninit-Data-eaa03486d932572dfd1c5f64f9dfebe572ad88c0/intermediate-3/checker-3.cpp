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
#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track whether a variable "ret" is uninitialized.
// The key is the memory region corresponding to the variable, and the value is
// true for uninitialized and false when it has been initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(UninitRetMap, const MemRegion *, bool)

namespace {

// This checker tracks the local variable "ret". It marks "ret" as uninitialized
// if it is declared without an initializer, updates the state when it is assigned,
// and reports a bug if an uninitialized "ret" is used as the return value.
//
// We use three callbacks:
//   - checkPostStmt on DeclStmt to record "ret" declarations.
//   - checkBind to mark "ret" as initialized when an assignment is made.
//   - checkPreStmt on ReturnStmt to report a bug if an uninitialized "ret"
//     is returned.
class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                          check::Bind,
                                          check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Uninitialized 'ret' use")) {}

  // Callback to track the declaration of local variables.
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;

  // Callback to track assignment events.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

  // Callback to detect a return statement using an uninitialized "ret".
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Iterate over each declaration in the declaration statement.
  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    // Only interested in a variable named "ret"
    if (VD->getName() != "ret")
      continue;

    // Only consider integer variables (as per bug pattern)
    if (!VD->getType()->isIntegerType())
      continue;

    // If the variable "ret" is declared with an initializer then it is not an issue.
    if (VD->hasInit())
      continue;

    // Create a DeclRefExpr for the variable to obtain its memory region.
    DeclarationNameInfo DNI(VD->getDeclName(), DS->getBeginLoc());
    // Use the constructor directly to create a DeclRefExpr.
    DeclRefExpr *DRE = new (C.getASTContext()) 
        DeclRefExpr(VD, /*HadDeclRefExpr=*/false, VD->getType(), VK_LValue, DS->getBeginLoc(), DNI, nullptr);
    const MemRegion *MR = getMemRegionFromExpr(DRE, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Mark the variable "ret" as uninitialized (true).
    State = State->set<UninitRetMap>(MR, true);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Get the memory region corresponding to the left-hand side of the assignment.
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // If this memory region was previously recorded as an uninitialized "ret",
  // then mark it as initialized because it is now being assigned a value.
  const bool *IsUninit = State->get<UninitRetMap>(MR);
  if (IsUninit && *IsUninit) {
    State = State->set<UninitRetMap>(MR, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  // Get the memory region of the returned expression.
  const MemRegion *MR = getMemRegionFromExpr(RetE, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Check if this return expression corresponds to a "ret" variable
  // that remains uninitialized.
  const bool *IsUninit = State->get<UninitRetMap>(MR);
  if (IsUninit && *IsUninit) {
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Uninitialized 'ret' used as return value", N);
      C.emitReport(std::move(Report));
    }
  }
  
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects uninitialized use of the local 'ret' variable in return statements", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
