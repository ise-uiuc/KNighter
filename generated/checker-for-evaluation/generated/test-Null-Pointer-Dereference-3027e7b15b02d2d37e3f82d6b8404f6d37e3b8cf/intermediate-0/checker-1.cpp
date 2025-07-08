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
// Additional includes if necessary
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to record if a pointer returned by devm_kasprintf has been NULL-checked.
// false => not checked; true => checked.
REGISTER_MAP_WITH_PROGRAMSTATE(PossibleNullPtrMap, const MemRegion*, bool)
// Optional program state map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Helper function to mark a given memory region (and its alias, if any) as checked.
ProgramStateRef setChecked(ProgramStateRef State, const MemRegion *MR) {
  if (!MR)
    return State;
  
  State = State->set<PossibleNullPtrMap>(MR, true);
  
  // Propagate to alias if exists.
  if (const MemRegion *const *AliasPtr = State->get<PtrAliasMap>(MR))
    State = State->set<PossibleNullPtrMap>(*AliasPtr, true);
  
  return State;
}

/// Helper: Checks if the current call is for devm_kasprintf.
static bool isDevmKasprintf(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  // Use ExprHasName for accurate checking.
  return ExprHasName(OriginExpr, "devm_kasprintf", C);
}

class SAGenTestChecker : public Checker<
      check::PostCall,         // To intercept devm_kasprintf return
      check::BranchCondition,  // To mark pointer as checked if tested against NULL
      check::Location,         // To flag dereferences of unchecked devm_kasprintf pointers
      check::Bind              // To propagate pointer aliasing information
    > {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked devm_kasprintf() return", "Null Dereference")) {}

  // Callback declarations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  
private:
  // Helper to report bug.
  void reportUncheckedDereference(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

/// checkPostCall: When a devm_kasprintf call returns, mark its returned pointer as unchecked.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!isDevmKasprintf(Call, C))
    return;
  
  // Retrieve the return value's memory region.
  // Do NOT call IgnoreImplicit() before getMemRegionFromExpr.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  if (!MR)
    return;
  
  // Mark as unchecked (false) because no NULL check has been performed yet.
  State = State->set<PossibleNullPtrMap>(MR, false);
  C.addTransition(State);
}

/// checkBranchCondition: If the condition performs a NULL check on a pointer,
/// mark that pointer (and its alias) as checked.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  CondE = CondE->IgnoreParenCasts();
  
  // Case 1: if(!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      SVal SubVal = State->getSVal(SubE, C.getLocationContext());
      if (const MemRegion *MR = SubVal.getAsRegion()) {
        MR = MR->getBaseRegion();
        State = setChecked(State, MR);
      }
    }
  }
  // Case 2: if(ptr == NULL) or if(ptr != NULL)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                          Expr::NPC_ValueDependentIsNull);
      bool RHIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                          Expr::NPC_ValueDependentIsNull);
      const Expr *PtrExpr = nullptr;
      if (LHIsNull && !RHIsNull)
        PtrExpr = RHS;
      else if (RHIsNull && !LHIsNull)
        PtrExpr = LHS;
      
      if (PtrExpr) {
        SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
        if (const MemRegion *MR = PtrVal.getAsRegion()) {
          MR = MR->getBaseRegion();
          State = setChecked(State, MR);
        }
      }
    }
  }
  // Case 3: if(ptr) -- a non-explicit NULL check condition; assume pointer is being tested.
  else {
    SVal CondVal = State->getSVal(CondE, C.getLocationContext());
    if (const MemRegion *MR = CondVal.getAsRegion()) {
      MR = MR->getBaseRegion();
      State = setChecked(State, MR);
    }
  }
  C.addTransition(State);
}

/// checkLocation: When a pointer is dereferenced (load or store), check if
/// the pointer returned by devm_kasprintf() is still unchecked.
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // We only care about pointer dereferences.
  if (const MemRegion *MR = Loc.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    const bool *Checked = State->get<PossibleNullPtrMap>(MR);
    // If the pointer was produced by devm_kasprintf (i.e. exists in our map)
    // and it is still unchecked, then warn if it is about to be dereferenced.
    if (Checked && (*Checked == false)) {
      reportUncheckedDereference(MR, S, C);
    }
  }
}

/// checkBind: When a pointer value is bound to a memory region (e.g. assignment),
/// record an aliasing relationship.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (!RHSReg)
        return;
      State = State->set<PtrAliasMap>(LHSReg, RHSReg);
      State = State->set<PtrAliasMap>(RHSReg, LHSReg);
    }
  }
  C.addTransition(State);
}

/// reportUncheckedDereference: Generate a non-fatal error node and report the bug.
void SAGenTestChecker::reportUncheckedDereference(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked devm_kasprintf() return may be NULL", N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of devm_kasprintf() return value without NULL checking", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
