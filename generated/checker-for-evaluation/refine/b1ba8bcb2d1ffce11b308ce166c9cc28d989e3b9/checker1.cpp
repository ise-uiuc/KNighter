// /scratch/chenyuan-data/SAGEN/result-0224-bugfail-multi-o3mini/test-Null-Pointer-Dereference-b1ba8bcb2d1ffce11b308ce166c9cc28d989e3b9/checkers/checker2.cpp
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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map for recording optional pointer allocation state.
// The bool flag indicates whether the pointer was checked for NULL (true means checked).
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion *, bool)
// Program state map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Mark the optional pointer as checked in the program state, and also update its alias.
/// This function sets the flag for the given region to true.
ProgramStateRef markOptionalPtrChecked(ProgramStateRef State, const MemRegion *MR) {
  if (!MR)
    return State;
  // Mark the current region as checked.
  State = State->set<OptionalPtrMap>(MR, true);
  // Update the alias info if any.
  const MemRegion *const *AliasPtr = State->get<PtrAliasMap>(MR);
  if (AliasPtr && *AliasPtr)
    State = State->set<OptionalPtrMap>(*AliasPtr, true);
  return State;
}

/// Checker class that detects dereferences of an optional pointer (returned by
/// devm_gpiod_get_array_optional) without a proper NULL check.
class SAGenTestChecker : public Checker<check::PostCall, check::BranchCondition, check::Bind, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Optional pointer dereference", "NULL Check")) {}

  // Callback: After a function call is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback: When analyzing a branch condition.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  // Callback: When a value is bound to a memory location (for tracking pointer aliases).
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  // Callback: When a memory location is accessed (dereferenced).
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Reports a bug when an optional pointer is dereferenced before a NULL check.
  void reportUncheckedDereference(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Intercept calls to devm_gpiod_get_array_optional.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use utility function to accurately check function name.
  if (!ExprHasName(OriginExpr, "devm_gpiod_get_array_optional", C))
    return;

  // Get the memory region associated with the call's return value.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Record the optional pointer in the state and initially mark it as not checked.
  State = State->set<OptionalPtrMap>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!Condition) {
    C.addTransition(State);
    return;
  }

  // Try to cast the condition to an expression.
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr) {
    C.addTransition(State);
    return;
  }

  // Remove any parentheses or implicit casts.
  CondExpr = CondExpr->IgnoreParenCasts();

  // Check for conditions that check the pointer.
  // Case 1: if (!ptr)
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(CondExpr)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubExpr = UO->getSubExpr()->IgnoreParenCasts();
      SVal SubVal = C.getState()->getSVal(SubExpr, C.getLocationContext());
      if (const MemRegion *MR = SubVal.getAsRegion()) {
        MR = MR->getBaseRegion();
        State = markOptionalPtrChecked(State, MR);
      }
    }
  }
  // Case 2: if (ptr != NULL) or if (ptr == NULL)
  else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondExpr)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_NE || Op == BO_EQ) {
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
        SVal PtrVal = C.getState()->getSVal(PtrExpr, C.getLocationContext());
        if (const MemRegion *MR = PtrVal.getAsRegion()) {
          MR = MR->getBaseRegion();
          State = markOptionalPtrChecked(State, MR);
        }
      }
    }
  }
  // Case 3: if (ptr) 
  else {
    SVal CondVal = C.getState()->getSVal(CondExpr, C.getLocationContext());
    if (const MemRegion *MR = CondVal.getAsRegion()) {
      MR = MR->getBaseRegion();
      State = markOptionalPtrChecked(State, MR);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // Get the left-hand side region.
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;
    
    // Get the right-hand side's region if available.
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (!RHSReg)
        return;
      
      // Record the alias relationship.
      State = State->set<PtrAliasMap>(LHSReg, RHSReg);
      State = State->set<PtrAliasMap>(RHSReg, LHSReg);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  
  // We are interested in memory dereferences.
  if (const MemRegion *MR = Loc.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    
    const bool *Checked = State->get<OptionalPtrMap>(MR);
    // If the pointer is recorded and has not been checked for NULL,
    // then report a bug.
    if (Checked && *Checked == false) {
      reportUncheckedDereference(MR, S, C);
    }
  }
}

void SAGenTestChecker::reportUncheckedDereference(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  // Create a diagnostic location using the source range of the statement.
  PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(S, C.getSourceManager(), C.getLocationContext());
  auto Report = std::make_unique<BasicBugReport>(
      *BT, "Optional pointer not checked for NULL before dereference", Loc);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects dereferencing of an optional pointer returned by devm_gpiod_get_array_optional "
      "without a prior NULL check", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
