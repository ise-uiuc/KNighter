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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/APInt.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track suspicious values and guards
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousVars, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(GuardedVars, const MemRegion *)

namespace {

class SAGenTestChecker
  : public Checker<
      check::PostStmt<DeclStmt>,
      check::Bind,
      check::BranchCondition
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Possible size_t underflow", "Integer errors")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      static bool isUnsignedType(QualType T);
      static bool isZeroExpr(const Expr *E, CheckerContext &C);
      static const MemRegion *getRegionIfVarOrField(const Expr *E, CheckerContext &C);
      static bool isRoundUpLike(const Expr *E, CheckerContext &C);
      static bool isSuspiciousMinus(const Expr *E, CheckerContext &C);
      static QualType getRegionValueType(const MemRegion *MR);
      static bool isSubAssignOnUnsigned(const BinaryOperator *BO, const MemRegion *LReg);
      static bool isAssignWithMinusOnUnsigned(const BinaryOperator *BO, const MemRegion *LReg, CheckerContext &C);
      static bool guardConditionMentionsVarGEorGT(const Expr *Cond, const MemRegion *VarR, CheckerContext &C);
      static bool branchSetsVarZero(const Stmt *S, const MemRegion *VarR, CheckerContext &C);
      static bool immediateIfGuardSetsVarZero(const Stmt *S, const MemRegion *VarR, CheckerContext &C);

      void markSuspicious(const MemRegion *R, CheckerContext &C) const;
      void clearSuspicious(const MemRegion *R, CheckerContext &C) const;
      void clearGuard(const MemRegion *R, CheckerContext &C) const;
      void reportUnderflow(const Stmt *S, CheckerContext &C) const;
};

// ---------------- Helper Implementations ----------------

bool SAGenTestChecker::isUnsignedType(QualType T) {
  if (T.isNull()) return false;
  return T->isUnsignedIntegerType();
}

bool SAGenTestChecker::isZeroExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
    return IL->getValue() == 0;
  }
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    return Res == 0;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getRegionIfVarOrField(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

bool SAGenTestChecker::isRoundUpLike(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  // Name-based detection; handles function-like macros or functions.
  if (ExprHasName(E, "round_up", C)) return true;
  if (ExprHasName(E, "roundup", C)) return true;
  if (ExprHasName(E, "ALIGN_UP", C)) return true;
  if (ExprHasName(E, "ALIGN", C)) return true; // common Linux macro
  return false;
}

bool SAGenTestChecker::isSuspiciousMinus(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO) return false;
  if (BO->getOpcode() != BO_Sub) return false;

  const Expr *RHS = BO->getRHS();
  if (!RHS) return false;
  if (isRoundUpLike(RHS, C))
    return true;

  // Also consider nested patterns like (A - ALIGN(B, C)) appearing under casts.
  return false;
}

QualType SAGenTestChecker::getRegionValueType(const MemRegion *MR) {
  if (!MR) return QualType();
  MR = MR->getBaseRegion();
  if (const auto *VR = dyn_cast<VarRegion>(MR))
    return VR->getDecl()->getType();
  if (const auto *FR = dyn_cast<FieldRegion>(MR))
    return FR->getDecl()->getType();
  return QualType();
}

bool SAGenTestChecker::isSubAssignOnUnsigned(const BinaryOperator *BO, const MemRegion *LReg) {
  if (!BO || !LReg) return false;
  if (BO->getOpcode() != BO_SubAssign) return false;
  return isUnsignedType(getRegionValueType(LReg));
}

bool SAGenTestChecker::isAssignWithMinusOnUnsigned(const BinaryOperator *BO, const MemRegion *LReg, CheckerContext &C) {
  if (!BO || !LReg) return false;
  if (BO->getOpcode() != BO_Assign) return false;
  if (!isUnsignedType(getRegionValueType(LReg))) return false;
  const Expr *RHS = BO->getRHS();
  if (!RHS) return false;
  RHS = RHS->IgnoreParenCasts();
  const auto *RBO = dyn_cast<BinaryOperator>(RHS);
  if (!RBO) return false;
  if (RBO->getOpcode() != BO_Sub) return false;
  return true;
}

bool SAGenTestChecker::guardConditionMentionsVarGEorGT(const Expr *Cond, const MemRegion *VarR, CheckerContext &C) {
  if (!Cond || !VarR) return false;

  // DFS through the condition's AST
  SmallVector<const Stmt *, 8> Worklist;
  Worklist.push_back(Cond);
  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (const auto *BE = dyn_cast<BinaryOperator>(Cur)) {
      BinaryOperator::Opcode Op = BE->getOpcode();
      if (Op == BO_GE || Op == BO_GT) {
        const MemRegion *L = getRegionIfVarOrField(BE->getLHS(), C);
        const MemRegion *R = getRegionIfVarOrField(BE->getRHS(), C);
        if ((L && L->getBaseRegion() == VarR->getBaseRegion()) ||
            (R && R->getBaseRegion() == VarR->getBaseRegion())) {
              return true;
        }
      }
    }
    for (const Stmt *Child : Cur->children()) {
      if (Child) Worklist.push_back(Child);
    }
  }
  return false;
}

bool SAGenTestChecker::branchSetsVarZero(const Stmt *S, const MemRegion *VarR, CheckerContext &C) {
  if (!S || !VarR) return false;
  SmallVector<const Stmt *, 16> Worklist;
  Worklist.push_back(S);
  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (const auto *BO = dyn_cast<BinaryOperator>(Cur)) {
      if (BO->getOpcode() == BO_Assign) {
        const MemRegion *LReg = getRegionIfVarOrField(BO->getLHS(), C);
        if (LReg && LReg->getBaseRegion() == VarR->getBaseRegion()) {
          if (const Expr *RHS = BO->getRHS()) {
            if (isZeroExpr(RHS, C))
              return true;
          }
        }
      }
    }
    for (const Stmt *Child : Cur->children()) {
      if (Child) Worklist.push_back(Child);
    }
  }
  return false;
}

bool SAGenTestChecker::immediateIfGuardSetsVarZero(const Stmt *S, const MemRegion *VarR, CheckerContext &C) {
  if (!S || !VarR) return false;
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(S, C);
  if (!CS) return false;

  // Find S in CS body and inspect the immediate previous statement if any
  const Stmt *Prev = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (Child == S) break;
    Prev = Child;
  }
  if (!Prev) return false;

  if (const auto *IfS = dyn_cast<IfStmt>(Prev)) {
    const Expr *Cond = IfS->getCond();
    if (guardConditionMentionsVarGEorGT(Cond, VarR, C)) {
      const Stmt *Then = IfS->getThen();
      if (Then && branchSetsVarZero(Then, VarR, C))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::markSuspicious(const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ProgramStateRef State = C.getState();
  if (!State->contains<SuspiciousVars>(R))
    State = State->add<SuspiciousVars>(R);
  // Recompute guard; new value invalidates guard assumptions
  if (State->contains<GuardedVars>(R))
    State = State->remove<GuardedVars>(R);
  C.addTransition(State);
}

void SAGenTestChecker::clearSuspicious(const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ProgramStateRef State = C.getState();
  if (State->contains<SuspiciousVars>(R))
    State = State->remove<SuspiciousVars>(R);
  if (State->contains<GuardedVars>(R))
    State = State->remove<GuardedVars>(R);
  C.addTransition(State);
}

void SAGenTestChecker::clearGuard(const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ProgramStateRef State = C.getState();
  if (State->contains<GuardedVars>(R))
    State = State->remove<GuardedVars>(R);
  C.addTransition(State);
}

void SAGenTestChecker::reportUnderflow(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Subtracting (avail - round_up(...)) from length without bound check may underflow",
      N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS) return;
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD) continue;
    if (!VD->hasInit()) continue;

    QualType T = VD->getType();
    if (!isUnsignedType(T)) continue;

    const Expr *Init = VD->getInit();
    if (!Init) continue;

    if (isSuspiciousMinus(Init, C)) {
      // Get the region for this variable
      MemRegionManager &MRMgr = C.getState()->getStateManager().getRegionManager();
      const MemRegion *R = MRMgr.getVarRegion(VD, C.getLocationContext());
      if (!R) continue;
      R = R->getBaseRegion();
      markSuspicious(R, C);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *LReg = Loc.getAsRegion();
  if (LReg) LReg = LReg->getBaseRegion();

  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);

  // Case A: Detect suspicious assignment/initialization into a variable/field
  if (LReg) {
    // If S is an assignment: X = (A - round_up(...))
    if (BO && BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS();
      if (RHS && isUnsignedType(getRegionValueType(LReg))) {
        if (isSuspiciousMinus(RHS, C)) {
          markSuspicious(LReg, C);
        } else if (isZeroExpr(RHS, C)) {
          // Reset if assigned zero
          clearSuspicious(LReg, C);
        } else {
          // Reassignment to something else drops the guard but may keep suspiciousness if unchanged.
          // Since we can't know, be conservative: drop guard only.
          clearGuard(LReg, C);
        }
      }
    } else {
      // Initialization via binding with RHS expression directly (not a BinaryOperator assign)
      if (const auto *RE = dyn_cast_or_null<Expr>(S)) {
        if (isUnsignedType(getRegionValueType(LReg)) && isSuspiciousMinus(RE, C)) {
          markSuspicious(LReg, C);
        }
      }
    }
  }

  // Case B: Detect dangerous subtract: Y -= X
  if (BO && isSubAssignOnUnsigned(BO, LReg)) {
    const Expr *RHS = BO->getRHS();
    // B1: RHS is a suspicious variable
    if (const MemRegion *RHSReg = getRegionIfVarOrField(RHS, C)) {
      ProgramStateRef State = C.getState();
      if (State->contains<SuspiciousVars>(RHSReg)) {
        bool Guarded = State->contains<GuardedVars>(RHSReg);
        bool LocalGuard = immediateIfGuardSetsVarZero(S, RHSReg, C);
        if (!Guarded && !LocalGuard) {
          reportUnderflow(S, C);
        }
      }
    } else {
      // B2: RHS is directly (A - round_up(...))
      if (isSuspiciousMinus(RHS, C)) {
        // Optional heuristic: look for immediate guard setting to zero; we can't map to a var here
        if (!immediateIfGuardSetsVarZero(S, nullptr, C))
          reportUnderflow(S, C);
      }
    }
  }

  // Case C: Detect dangerous subtract: Y = Y - X
  if (BO && isAssignWithMinusOnUnsigned(BO, LReg, C)) {
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    const auto *RBO = dyn_cast<BinaryOperator>(RHS);
    if (RBO && RBO->getOpcode() == BO_Sub) {
      const Expr *SubRHS = RBO->getRHS();
      if (const MemRegion *RHSReg = getRegionIfVarOrField(SubRHS, C)) {
        ProgramStateRef State = C.getState();
        if (State->contains<SuspiciousVars>(RHSReg)) {
          bool Guarded = State->contains<GuardedVars>(RHSReg);
          bool LocalGuard = immediateIfGuardSetsVarZero(S, RHSReg, C);
          if (!Guarded && !LocalGuard) {
            reportUnderflow(S, C);
          }
        }
      } else if (isSuspiciousMinus(SubRHS, C)) {
        if (!immediateIfGuardSetsVarZero(S, nullptr, C))
          reportUnderflow(S, C);
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) return;

  ProgramStateRef State = C.getState();

  // Scan condition for GE/GT comparisons involving suspicious vars and mark as guarded.
  SmallVector<const Stmt *, 8> Worklist;
  Worklist.push_back(CondE);
  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (const auto *BE = dyn_cast<BinaryOperator>(Cur)) {
      BinaryOperator::Opcode Op = BE->getOpcode();
      if (Op == BO_GE || Op == BO_GT) {
        const MemRegion *L = getRegionIfVarOrField(BE->getLHS(), C);
        const MemRegion *R = getRegionIfVarOrField(BE->getRHS(), C);
        if (L && State->contains<SuspiciousVars>(L))
          State = State->add<GuardedVars>(L);
        if (R && State->contains<SuspiciousVars>(R))
          State = State->add<GuardedVars>(R);
      }
    }
    for (const Stmt *Child : Cur->children()) {
      if (Child) Worklist.push_back(Child);
    }
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects subtracting (avail - round_up(...)) from an unsigned length without guard, which may underflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
