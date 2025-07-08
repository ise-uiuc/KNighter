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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: map the firmware pointer's MemRegion to a bool flag.
// false: firmware pointer not checked for failure;
// true: firmware pointer has been checked.
REGISTER_MAP_WITH_PROGRAMSTATE(FWInitMap, const MemRegion*, bool)
// Optionally, track alias relationships for firmware pointers.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Helper function to mark a firmware pointer region (and its alias, if any) as checked.
ProgramStateRef markFwChecked(ProgramStateRef State, const MemRegion *MR) {
  if (!MR)
    return State;
  State = State->set<FWInitMap>(MR, true);
  // Update any alias if available.
  if (const auto *AliasPtr = State->get<PtrAliasMap>(MR))
    State = State->set<FWInitMap>(*AliasPtr, true);
  return State;
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::BranchCondition, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Uninitialized Firmware Pointer", "Firmware Loading")) {}

  // Callback: Called after a function call is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback: Called before a function call is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback: Called when evaluating a branch condition.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  // Callback: Called when a value is bound to a memory region.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
};

/// checkPostCall:
/// For calls to request_firmware: record the firmware pointer as unchecked.
/// The firmware pointer argument is the first argument to request_firmware.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Use helper to get the source text and check name.
  if (ExprHasName(OriginExpr, "request_firmware", C)) {
    // For request_firmware(&fw, file, dev), the firmware pointer is passed as the first argument.
    if (Call.getNumArgs() < 1)
      return;

    const Expr *FwArg = Call.getArgExpr(0);
    if (!FwArg)
      return;
    const MemRegion *MR = getMemRegionFromExpr(FwArg, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Mark the firmware pointer region as unchecked (false)
    State = State->set<FWInitMap>(MR, false);
    C.addTransition(State);
  }
}

/// checkBranchCondition:
/// Check if a branch condition checks the firmware pointer for NULL.
/// If yes, mark that firmware pointer as checked.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (!Condition) {
    C.addTransition(State);
    return;
  }

  // We are interested in conditions that check a pointer (like "if (!fw)" or "if (fw == NULL)").
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  CondE = CondE->IgnoreParenCasts();

  // Case 1: if (!fw)
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      const MemRegion *MR = getMemRegionFromExpr(SubE, C);
      if (MR) {
        MR = MR->getBaseRegion();
        State = markFwChecked(State, MR);
      }
    }
  }
  // Case 2: if (fw == NULL) or if (fw != NULL)
  else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      const Expr *FwExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        FwExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        FwExpr = LHS;
      if (FwExpr) {
        const MemRegion *MR = getMemRegionFromExpr(FwExpr, C);
        if (MR) {
          MR = MR->getBaseRegion();
          State = markFwChecked(State, MR);
        }
      }
    }
  }
  // Case 3: if(fw)  -- when used as a boolean value.
  else {
    const MemRegion *MR = getMemRegionFromExpr(CondE, C);
    if (MR) {
      MR = MR->getBaseRegion();
      State = markFwChecked(State, MR);
    }
  }
  C.addTransition(State);
}

/// checkPreCall:
/// For calls to release_firmware: check if the firmware pointer being released
/// was properly checked. If not, report a bug.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  if (!ExprHasName(OriginExpr, "release_firmware", C))
    return;

  // For release_firmware(fw), the firmware pointer is the first argument.
  if (Call.getNumArgs() < 1)
    return;
  const Expr *FwArg = Call.getArgExpr(0);
  if (!FwArg)
    return;
  const MemRegion *MR = getMemRegionFromExpr(FwArg, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const bool *Checked = State->get<FWInitMap>(MR);
  // If the firmware pointer exists in our map and is still unchecked, report a bug.
  if (Checked && *Checked == false) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Firmware pointer not checked for request failure", N);
    report->addRange(FwArg->getSourceRange());
    C.emitReport(std::move(report));
  }
}

/// checkBind:
/// When a value (firmware pointer) is assigned to another variable,
/// record the alias relationship in PtrAliasMap.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
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
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of firmware pointer without checking request_firmware() failure", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
