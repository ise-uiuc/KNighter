#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Lex/Lexer.h"
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

// Customize program states: Map firmware pointer regions to a checked flag (true if checked) and a
// pointer alias map to propagate the check.
REGISTER_MAP_WITH_PROGRAMSTATE(FirmwareInitMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall, check::BranchCondition, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked firmware initialization")) {}

  // Callback declarations.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
};

/// checkPostCall: After a call to request_firmware, mark the firmware pointer as unchecked.
/// We expect that the call has the firmware pointer address as its first argument.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Use utility to check function name.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "request_firmware", C))
    return;
  
  // The first argument to request_firmware should be a pointer to the firmware pointer.
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return;
  
  MR = MR->getBaseRegion();
  ProgramStateRef State = C.getState();
  // Mark the firmware pointer as unchecked (false).
  State = State->set<FirmwareInitMap>(MR, false);
  C.addTransition(State);
}

/// checkBranchCondition: When a branch condition is evaluated,
/// if it is checking the firmware pointer (e.g. if (!fw) or if (fw == NULL)),
/// mark the pointer as checked.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  CondE = CondE->IgnoreParenCasts();

  // Pattern 1: if (!fw)
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      SVal SV = State->getSVal(SubE, C.getLocationContext());
      if (const MemRegion *MR = SV.getAsRegion()) {
        MR = MR->getBaseRegion();
        State = State->set<FirmwareInitMap>(MR, true);
      }
    }
  }
  // Pattern 2: if (fw == NULL) or if (fw != NULL)
  else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
      
      if (PtrExpr) {
        SVal SV = State->getSVal(PtrExpr, C.getLocationContext());
        if (const MemRegion *MR = SV.getAsRegion()) {
          MR = MR->getBaseRegion();
          State = State->set<FirmwareInitMap>(MR, true);
        }
      }
    }
  }
  // Pattern 3: if (fw) simple non-null check.
  else {
    SVal SV = State->getSVal(CondE, C.getLocationContext());
    if (const MemRegion *MR = SV.getAsRegion()) {
      MR = MR->getBaseRegion();
      State = State->set<FirmwareInitMap>(MR, true);
    }
  }
  C.addTransition(State);
}

/// checkPreCall: Before calling release_firmware, check if the firmware pointer
/// has been NULL-checked. If not, report a bug.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "release_firmware", C))
    return;

  // For release_firmware, the first argument is the firmware pointer.
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<FirmwareInitMap>(MR);
  if (Checked && *Checked == false) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Unchecked firmware initialization: firmware pointer is not validated", N);
    C.emitReport(std::move(Report));
  }
}

/// checkBind: Track aliasing between firmware pointer variables.
// When a pointer is bound to another memory region, store the alias relationship.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (const MemRegion *LHS = Loc.getAsRegion()) {
    LHS = LHS->getBaseRegion();
    if (!LHS)
      return;
    if (const MemRegion *RHS = Val.getAsRegion()) {
      RHS = RHS->getBaseRegion();
      if (!RHS)
        return;
      State = State->set<PtrAliasMap>(LHS, RHS);
      State = State->set<PtrAliasMap>(RHS, LHS);
    }
  }
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects the use of firmware pointers returned by request_firmware without proper NULL-check", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
