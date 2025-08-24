```cpp
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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: map error variable region to the sq object region.
REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarSqMap, const MemRegion*, const MemRegion*)

namespace {

static const MemRegion *getBaseRegFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

static bool isCallNamed(const CallExpr *CE, StringRef Name, CheckerContext &C) {
  if (!CE)
    return false;
  const Expr *Callee = CE->getCallee();
  if (!Callee)
    return false;
  return ExprHasName(Callee, Name, C);
}

static const CallExpr *findCallByName(const Stmt *S, StringRef Name, CheckerContext &C) {
  if (!S)
    return nullptr;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (isCallNamed(CE, Name, C))
      return CE;
  }

  for (const Stmt *Child : S->children()) {
    if (const CallExpr *Found = findCallByName(Child, Name, C))
      return Found;
  }
  return nullptr;
}

static void collectDeclRefExprs(const Stmt *S, llvm::SmallVectorImpl<const DeclRefExpr *> &Out) {
  if (!S)
    return;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    Out.push_back(DRE);
  }
  for (const Stmt *Child : S->children())
    collectDeclRefExprs(Child, Out);
}

static const MemRegion *getSqRegionFromSetSqRdyCall(const CallExpr *CE, CheckerContext &C) {
  if (!CE)
    return nullptr;
  if (CE->getNumArgs() < 2)
    return nullptr;
  const Expr *Arg1 = CE->getArg(1);
  if (!Arg1)
    return nullptr;

  const Expr *E = Arg1; // Do not IgnoreImplicit before getMemRegionFromExpr as per suggestions.
  // Expecting MemberExpr referencing "sqn", get its base expression for 'sq'.
  if (const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts())) {
    const ValueDecl *VD = ME->getMemberDecl();
    if (!VD)
      return nullptr;
    if (VD->getName() != "sqn")
      return nullptr;
    const Expr *Base = ME->getBase();
    if (!Base)
      return nullptr;
    return getBaseRegFromExpr(Base, C);
  }

  // If not a MemberExpr, conservatively try to derive a region anyway (best-effort).
  return getBaseRegFromExpr(E, C);
}

static const MemRegion *getSqRegionFromCloseSqCall(const CallExpr *CE, CheckerContext &C) {
  if (!CE)
    return nullptr;
  if (CE->getNumArgs() < 1)
    return nullptr;
  const Expr *Arg0 = CE->getArg(0);
  if (!Arg0)
    return nullptr;
  return getBaseRegFromExpr(Arg0, C);
}

static bool branchHasDestroySq(const Stmt *Branch, CheckerContext &C) {
  if (!Branch)
    return false;
  if (findCallByName(Branch, "mlx5_core_destroy_sq", C))
    return true;
  if (findCallByName(Branch, "hws_send_ring_destroy_sq", C))
    return true;
  return false;
}

static bool isZeroIntegerLiteral(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C)) {
    return Val == 0;
  }
  return false;
}

// Decide if the failure branch is the 'then' or 'else' for an if-statement whose condition is CondE.
// Default: Then is failure. If condition is logically "err == 0" or "!err", then Else is failure.
static bool failureIsThen(const Expr *CondE, const MemRegion *ErrReg, CheckerContext &C) {
  if (!CondE || !ErrReg)
    return true;

  // Strip parens; keep implicit casts for region mapping when needed elsewhere.
  CondE = CondE->IgnoreParens();

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      // if (!err) -> failure is else-branch
      return false;
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (!BO->isComparisonOp())
      return true;

    const Expr *LHS = BO->getLHS();
    const Expr *RHS = BO->getRHS();

    const MemRegion *LHSReg = getBaseRegFromExpr(LHS, C);
    const MemRegion *RHSReg = getBaseRegFromExpr(RHS, C);

    bool LHSIsErr = (LHSReg && LHSReg == ErrReg);
    bool RHSIsErr = (RHSReg && RHSReg == ErrReg);

    // Only reason about cases comparing err to 0.
    if ((LHSIsErr && isZeroIntegerLiteral(RHS, C)) ||
        (RHSIsErr && isZeroIntegerLiteral(LHS, C))) {
      BinaryOperator::Opcode Op = BO->getOpcode();
      if (Op == BO_EQ) {
        // if (err == 0) -> failure is else-branch
        return false;
      }
      // if (err != 0), if (err < 0), etc. -> treat as failure in then-branch
      return true;
    }
  }

  // Default conservative choice: Then is failure.
  return true;
}

class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Over-broad cleanup in failure path", "API Misuse")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportAtCall(const CallExpr *CE, CheckerContext &C) const {
    if (!CE)
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Wrong cleanup on failure: hws_send_ring_close_sq may double free; use destroy_sq.", N);
    R->addRange(CE->getSourceRange());
    C.emitReport(std::move(R));
  }
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // We are interested in assignments like: err = hws_send_ring_set_sq_rdy(mdev, sq->sqn);
  const BinaryOperator *BO = findSpecificTypeInChildren<BinaryOperator>(S);
  if (!BO)
    return;
  if (BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  const MemRegion *ErrVarReg = getBaseRegFromExpr(LHS, C);
  if (!ErrVarReg)
    return;

  const CallExpr *RHSCall = findSpecificTypeInChildren<CallExpr>(RHS);
  if (!RHSCall)
    return;
  if (!isCallNamed(RHSCall, "hws_send_ring_set_sq_rdy", C))
    return;

  const MemRegion *SqReg = getSqRegionFromSetSqRdyCall(RHSCall, C);
  if (!SqReg)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<ErrVarSqMap>(ErrVarReg, SqReg);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();

  // Mode 1: direct call in condition: if (hws_send_ring_set_sq_rdy(mdev, sq->sqn)) { ... }
  if (const CallExpr *CondCall = findSpecificTypeInChildren<CallExpr>(CondE)) {
    if (isCallNamed(CondCall, "hws_send_ring_set_sq_rdy", C)) {
      const MemRegion *SqReg = getSqRegionFromSetSqRdyCall(CondCall, C);
      if (!SqReg)
        return;

      const Stmt *ThenS = IS->getThen();
      if (!ThenS)
        return;

      // If correct destroy is present, skip.
      if (branchHasDestroySq(ThenS, C))
        return;

      const CallExpr *CloseCall = findCallByName(ThenS, "hws_send_ring_close_sq", C);
      if (!CloseCall)
        return;

      const MemRegion *CloseArgReg = getSqRegionFromCloseSqCall(CloseCall, C);
      if (!CloseArgReg)
        return;

      if (CloseArgReg->getBaseRegion() == SqReg->getBaseRegion()) {
        reportAtCall(CloseCall, C);
      }
      return;
    }
  }

  // Mode 2: variable-checked pattern: if (err) { hws_send_ring_close_sq(sq); }
  // Find any DeclRefExpr in condition that matches a key in ErrVarSqMap.
  llvm::SmallVector<const DeclRefExpr *, 8> CondDREs;
  collectDeclRefExprs(CondE, CondDREs);

  const MemRegion *ErrVarReg = nullptr;
  const MemRegion *SqReg = nullptr;

  for (const DeclRefExpr *DRE : CondDREs) {
    const MemRegion *Reg = getBaseRegFromExpr(DRE, C);
    if (!Reg)
      continue;
    if (const MemRegion *const *MappedSq = State->get<ErrVarSqMap>(Reg)) {
      ErrVarReg = Reg;
      SqReg = *MappedSq;
      break;
    }
  }

  if (!ErrVarReg || !SqReg)
    return;

  bool ThenIsFailure = failureIsThen(CondE, ErrVarReg, C);
  const Stmt *FailureBranch = ThenIsFailure ? IS->getThen() : IS->getElse();
  if (!FailureBranch)
    return;

  if (branchHasDestroySq(FailureBranch, C))
    return;

  const CallExpr *CloseCall = findCallByName(FailureBranch, "hws_send_ring_close_sq", C);
  if (!CloseCall)
    return;

  const MemRegion *CloseArgReg = getSqRegionFromCloseSqCall(CloseCall, C);
  if (!CloseArgReg)
    return;

  if (CloseArgReg->getBaseRegion() == SqReg->getBaseRegion()) {
    reportAtCall(CloseCall, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects wrong cleanup on failure: using hws_send_ring_close_sq instead of the proper destroy_sq",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
