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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register program state maps.
// PossibleNullPtrMap tracks whether a given memory region (obtained from a
// devm_kasprintf call) has been checked for NULL.
// PtrAliasMap is used to record aliasing relationships between pointer regions.
REGISTER_MAP_WITH_PROGRAMSTATE(PossibleNullPtrMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                          check::BranchCondition,
                                          check::Bind,
                                          check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked devm_kasprintf return usage")) {}

  // Callback: invoked right after a function call is evaluated.
  // We intercept calls to devm_kasprintf and mark its returned memory region
  // in our PossibleNullPtrMap as unchecked (false).
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: invoked when evaluating branch conditions (e.g. in an if statement).
  // Examines conditions that look like NULL checks. If the pointer is being
  // checked, mark the corresponding region (and any aliases) as checked (true).
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

  // Callback: invoked when a value is bound to a memory region, used here to
  // propagate aliasing information between pointers.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Callback: invoked on explicit pointer dereference. If an unchecked pointer
  // from devm_kasprintf is about to be dereferenced, report a bug.
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to mark a given memory region as checked.
  ProgramStateRef setChecked(ProgramStateRef State, const MemRegion *MR) const;
};

ProgramStateRef SAGenTestChecker::setChecked(ProgramStateRef State, const MemRegion *MR) const {
  if (!MR)
    return State;
  // Mark the base region.
  State = State->set<PossibleNullPtrMap>(MR, true);
  // Also mark any alias, if present.
  if (const MemRegion *const *AliasPtr = State->get<PtrAliasMap>(MR))
    State = State->set<PossibleNullPtrMap>(*AliasPtr, true);
  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Identify calls to devm_kasprintf using the origin expression's source text.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "devm_kasprintf", C))
    return;
  // Obtain the memory region of the return value.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  // Mark the region as unchecked (false).
  State = State->set<PossibleNullPtrMap>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr) {
    C.addTransition(State);
    return;
  }
  
  // Remove any parentheses or implicit casts.
  CondExpr = CondExpr->IgnoreParenCasts();
  
  // Case 1: "if (!ptr)"
  if (const auto *UO = dyn_cast<UnaryOperator>(CondExpr)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubExpr = UO->getSubExpr()->IgnoreParenCasts();
      SVal SubVal = C.getState()->getSVal(SubExpr, C.getLocationContext());
      if (const MemRegion *MR = SubVal.getAsRegion()) {
        MR = MR->getBaseRegion();
        State = setChecked(State, MR);
      }
    }
  }
  // Case 2: "if (ptr == NULL)" or "if (ptr != NULL)"
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondExpr)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
      if (PtrExpr) {
        SVal Val = C.getState()->getSVal(PtrExpr, C.getLocationContext());
        if (const MemRegion *MR = Val.getAsRegion()) {
          MR = MR->getBaseRegion();
          State = setChecked(State, MR);
        }
      }
    }
  }
  // Case 3: General condition "if (ptr)"
  else {
    SVal Val = C.getState()->getSVal(CondExpr, C.getLocationContext());
    if (const MemRegion *MR = Val.getAsRegion()) {
      MR = MR->getBaseRegion();
      State = setChecked(State, MR);
    }
  }
  
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // If the left-hand side is a memory region, record aliasing information with the right-hand side.
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg) {
      C.addTransition(State);
      return;
    }
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (RHSReg) {
        State = State->set<PtrAliasMap>(LHSReg, RHSReg);
        State = State->set<PtrAliasMap>(RHSReg, LHSReg);
      }
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // When a pointer is dereferenced, check whether its memory region
  // (from devm_kasprintf) has been marked as checked.
  if (const MemRegion *MR = Loc.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    const bool *IsChecked = State->get<PossibleNullPtrMap>(MR);
    if (IsChecked && (*IsChecked == false)) {
      // Report a bug: the result of devm_kasprintf was used without a prior NULL check.
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unchecked devm_kasprintf return used", N);
      Report->addRange(S->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}
  
} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects usage of devm_kasprintf return without a preceding NULL check", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
