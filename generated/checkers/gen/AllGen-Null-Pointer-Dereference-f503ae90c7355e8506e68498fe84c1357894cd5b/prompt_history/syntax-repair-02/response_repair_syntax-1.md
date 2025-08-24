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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks pointers that may be NULL and are not yet checked.
// true => possibly NULL and unchecked; false => checked (non-NULL).
REGISTER_MAP_WITH_PROGRAMSTATE(PossiblyNullPtrMap, const MemRegion*, bool)
// Tracks pointer aliases created by assignments/copies.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::Bind,
      check::BranchCondition,
      check::PreStmt<MemberExpr>,
      check::PreStmt<UnaryOperator>
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "NULL dereference of capability pointer", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPreStmt(const MemberExpr *ME, CheckerContext &C) const;
      void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;

   private:
      // Helper: resolve alias root using PtrAliasMap (guard against cycles).
      const MemRegion* resolveRoot(const MemRegion *R, ProgramStateRef State) const;

      // Helper: check if a call is to a known nullable getter.
      bool isKnownNullableGetter(const CallEvent &Call, CheckerContext &C) const;

      // Helper: mark a pointer as checked in PossiblyNullPtrMap.
      ProgramStateRef markChecked(ProgramStateRef State, const MemRegion *R) const;

      // Helper: examine condition expression and extract a pointer expr if it's a NULL-check form.
      const Expr* getPtrExprFromCondition(const Expr *CondE, CheckerContext &C) const;

      // Reporting
      void reportPossibleNullDeref(const Stmt *S, CheckerContext &C) const;
};

const MemRegion* SAGenTestChecker::resolveRoot(const MemRegion *R, ProgramStateRef State) const {
  if (!R)
    return nullptr;

  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  Visited.insert(Cur);

  while (true) {
    const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur);
    if (!NextPtr)
      break;
    const MemRegion *Next = (*NextPtr)->getBaseRegion();
    if (Next == Cur)
      break;
    if (!Visited.insert(Next).second)
      break;
    Cur = Next;
  }
  return Cur;
}

bool SAGenTestChecker::isKnownNullableGetter(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "mt76_connac_get_he_phy_cap", C);
}

ProgramStateRef SAGenTestChecker::markChecked(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return State;
  const MemRegion *Root = resolveRoot(R, State);
  if (!Root)
    return State;

  const bool *Cur = State->get<PossiblyNullPtrMap>(Root);
  if (Cur && *Cur == true) {
    State = State->set<PossiblyNullPtrMap>(Root, false);
  }
  return State;
}

const Expr* SAGenTestChecker::getPtrExprFromCondition(const Expr *CondE, CheckerContext &C) const {
  if (!CondE)
    return nullptr;

  CondE = CondE->IgnoreParenCasts();

  // if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr();
      return SubE ? SubE->IgnoreParenCasts() : nullptr;
    }
  }

  // if (ptr == NULL) or if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      llvm::APSInt Val;
      bool LHSIsZero = EvaluateExprToInt(Val, LHS, C) && Val == 0;
      bool RHSIsZero = EvaluateExprToInt(Val, RHS, C) && Val == 0;

      if (!LHSIsZero && RHSIsZero)
        return LHS;
      if (!RHSIsZero && LHSIsZero)
        return RHS;

      // Fallback for macro NULL name
      if (!LHSIsZero && ExprHasName(RHS, "NULL", C))
        return LHS;
      if (!RHSIsZero && ExprHasName(LHS, "NULL", C))
        return RHS;
    }
  }

  // if (ptr)
  // For bare pointer in condition, we consider it a check use.
  return CondE;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isKnownNullableGetter(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return;

  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark return value as possibly NULL and unchecked.
  State = State->set<PossiblyNullPtrMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }

  // If binding a pointer value from another region, record alias and propagate status.
  if (const MemRegion *RHSReg = Val.getAsRegion()) {
    RHSReg = RHSReg->getBaseRegion();
    if (RHSReg) {
      const MemRegion *LRoot = resolveRoot(LHSReg, State);
      const MemRegion *RRoot = resolveRoot(RHSReg, State);
      if (LRoot && RRoot) {
        State = State->set<PtrAliasMap>(LRoot, RRoot);
        State = State->set<PtrAliasMap>(RRoot, LRoot);

        if (const bool *Flag = State->get<PossiblyNullPtrMap>(RRoot)) {
          State = State->set<PossiblyNullPtrMap>(LRoot, *Flag);
        }
      }
    }
  } else {
    // If assigned a concrete NULL, mark as possibly NULL and unchecked.
    if (Val.isZeroConstant()) {
      const MemRegion *LRoot = resolveRoot(LHSReg, State);
      if (LRoot)
        State = State->set<PossiblyNullPtrMap>(LRoot, true);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(C.getState());
    return;
  }

  const Expr *PtrExpr = getPtrExprFromCondition(CondE, C);
  if (!PtrExpr) {
    C.addTransition(C.getState());
    return;
  }

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(PtrExpr, C);
  if (MR) {
    MR = MR->getBaseRegion();
    if (MR) {
      State = markChecked(State, MR);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const MemberExpr *ME, CheckerContext &C) const {
  if (!ME || !ME->isArrow())
    return;

  const Expr *Base = ME->getBase();
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(Base, C);
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const MemRegion *Root = resolveRoot(MR, State);
  if (!Root)
    return;

  const bool *Flag = State->get<PossiblyNullPtrMap>(Root);
  if (Flag && *Flag) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Possible NULL dereference of capability pointer (mt76_connac_get_he_phy_cap)", N);
    R->addRange(ME->getSourceRange());
    C.emitReport(std::move(R));
  }
}

void SAGenTestChecker::checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const {
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *SubE = UO->getSubExpr();
  if (!SubE)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(SubE, C);
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const MemRegion *Root = resolveRoot(MR, State);
  if (!Root)
    return;

  const bool *Flag = State->get<PossiblyNullPtrMap>(Root);
  if (Flag && *Flag) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Possible NULL dereference of capability pointer (mt76_connac_get_he_phy_cap)", N);
    R->addRange(UO->getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereferencing result of mt76_connac_get_he_phy_cap without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
