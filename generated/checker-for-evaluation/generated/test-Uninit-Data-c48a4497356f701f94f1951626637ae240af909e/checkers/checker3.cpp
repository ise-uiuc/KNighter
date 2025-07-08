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
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states.
// FirmwareInitMap maps a firmware pointer's MemRegion (e.g. for fw) to a bool indicating whether it has been checked.
REGISTER_MAP_WITH_PROGRAMSTATE(FirmwareInitMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Uninitialized Firmware Pointer",
                       "Failure to check request_firmware's initialization result")) {}

  // Callback for after a function call is evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback for before a function call is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback for branch conditions (e.g. in if/while).
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper: Mark the firmware pointer as checked.
  ProgramStateRef markFirmwareChecked(ProgramStateRef State, const MemRegion *MR) const {
    if (!MR)
      return State;
    MR = MR->getBaseRegion();
    // Mark as checked by setting the boolean to true.
    return State->set<FirmwareInitMap>(MR, true);
  }

  // Helper: Report bug when release_firmware is called on unchecked firmware pointer.
  void reportUninitFirmware(const CallEvent &Call, CheckerContext &C, const MemRegion *MR) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "release_firmware called on firmware pointer that was not checked for initialization", N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  }
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept calls to request_firmware.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Use utility function to check the function name.
  if (!ExprHasName(OriginExpr, "request_firmware", C))
    return;

  // For request_firmware, the first argument is the address of the firmware pointer.
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;
  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  ProgramStateRef State = C.getState();
  // Mark firmware pointer region as unchecked (false) to indicate that its return
  // value was not verified.
  State = State->set<FirmwareInitMap>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Check whether the condition performs a NULL-check on the firmware pointer.
  // We look for patterns such as "if (!fw)" or "if (fw == NULL)".
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  // Strip off any parentheses or casts.
  CondE = CondE->IgnoreParenCasts();

  // Handle "if (!fw)".
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      SVal SubVal = State->getSVal(SubE, C.getLocationContext());
      if (const MemRegion *MR = SubVal.getAsRegion()) {
        State = markFirmwareChecked(State, MR);
      }
    }
  }
  // Handle binary comparisons: "if (fw == NULL)" or "if (fw != NULL)".
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
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
        SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
        if (const MemRegion *MR = PtrVal.getAsRegion()) {
          State = markFirmwareChecked(State, MR);
        }
      }
    }
  }
  // Also, if the condition itself references the firmware pointer in a boolean context,
  // we mark it as checked.
  else {
    SVal CondVal = State->getSVal(CondE, C.getLocationContext());
    if (const MemRegion *MR = CondVal.getAsRegion()) {
      State = markFirmwareChecked(State, MR);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Intercept calls to release_firmware.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "release_firmware", C))
    return;

  // For release_firmware, the first (and only) argument is the firmware pointer.
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;
  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<FirmwareInitMap>(MR);
  // If the firmware pointer was never marked as checked, then this is a bug.
  if (Checked && *Checked == false) {
    reportUninitFirmware(Call, C, MR);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of an uninitialized firmware pointer due to missing request_firmware check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
