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
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track pointer-like regions that may come from "optional" getters.
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion*, unsigned)
// Map the return symbol of optional getter calls; used to transfer tag on bind.
REGISTER_MAP_WITH_PROGRAMSTATE(OptRetSymMap, SymbolRef, char)

namespace {

static constexpr unsigned FromOptionalGetter = 1u;   // bit0
static constexpr unsigned NullCheckedObserved = 2u;  // bit1
static constexpr unsigned ErrCheckedObserved  = 4u;  // bit2

class SAGenTestChecker : public Checker<
  check::PostCall,
  check::Bind,
  check::BranchCondition,
  check::Location
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Optional resource NULL dereference", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helper predicates and state updaters
      static bool isOptionalGetterName(StringRef N);
      static bool isOptionalGetterExpr(const Expr *E, CheckerContext &C);

      static bool isIS_ERR_Name(const Expr *E, CheckerContext &C);
      static bool isIS_ERR_OR_NULL_Name(const Expr *E, CheckerContext &C);

      static ProgramStateRef overwriteFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Flags);
      static ProgramStateRef orFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Mask);

      const MemRegion *getTrackedRegionFromExpr(const Expr *E, CheckerContext &C, ProgramStateRef State) const;
      const MemRegion *getFirstTrackedRegionInCondition(const Stmt *Condition, CheckerContext &C) const;

      const Expr *getDerefBaseExpr(const Stmt *S, CheckerContext &C) const;

      void reportDerefWithoutNullCheck(const Stmt *S, unsigned Flags, CheckerContext &C) const;
};

// -------- Helpers --------

bool SAGenTestChecker::isOptionalGetterName(StringRef N) {
  return N.equals("devm_gpiod_get_array_optional") ||
         N.equals("gpiod_get_array_optional")      ||
         N.equals("devm_gpiod_get_optional")       ||
         N.equals("gpiod_get_optional");
}

bool SAGenTestChecker::isOptionalGetterExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "devm_gpiod_get_array_optional", C) ||
         ExprHasName(E, "gpiod_get_array_optional", C)      ||
         ExprHasName(E, "devm_gpiod_get_optional", C)       ||
         ExprHasName(E, "gpiod_get_optional", C);
}

bool SAGenTestChecker::isIS_ERR_Name(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "IS_ERR", C);
}

bool SAGenTestChecker::isIS_ERR_OR_NULL_Name(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "IS_ERR_OR_NULL", C);
}

ProgramStateRef SAGenTestChecker::overwriteFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Flags) {
  if (!BaseReg) return State;
  return State->set<OptionalPtrMap>(BaseReg, Flags);
}

ProgramStateRef SAGenTestChecker::orFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Mask) {
  if (!BaseReg) return State;
  const unsigned *Old = State->get<OptionalPtrMap>(BaseReg);
  unsigned NewFlags = (Old ? *Old : 0u) | Mask;
  return State->set<OptionalPtrMap>(BaseReg, NewFlags);
}

const MemRegion *SAGenTestChecker::getTrackedRegionFromExpr(const Expr *E, CheckerContext &C, ProgramStateRef State) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  if (!MR) return nullptr;
  if (State->get<OptionalPtrMap>(MR))
    return MR;
  return nullptr;
}

const MemRegion *SAGenTestChecker::getFirstTrackedRegionInCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Try call-expression based checks first (IS_ERR/IS_ERR_OR_NULL)
  if (const auto *CE = findSpecificTypeInChildren<CallExpr>(Condition)) {
    if (isIS_ERR_Name(CE, C) || isIS_ERR_OR_NULL_Name(CE, C)) {
      if (CE->getNumArgs() >= 1) {
        if (const Expr *Arg0 = CE->getArg(0)) {
          if (const MemRegion *MR = getTrackedRegionFromExpr(Arg0, C, State))
            return MR;
        }
      }
    }
  }

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) return nullptr;
  CondE = CondE->IgnoreParenCasts();

  // Binary: ptr == NULL or ptr != NULL
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenCasts();
      const Expr *R = BO->getRHS()->IgnoreParenCasts();
      bool LIsNull = L->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RIsNull = R->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      const Expr *PtrE = nullptr;
      if (LIsNull && !RIsNull) PtrE = R;
      else if (RIsNull && !LIsNull) PtrE = L;
      if (PtrE) {
        if (const MemRegion *MR = getTrackedRegionFromExpr(PtrE, C, State))
          return MR;
      }
    }
  }

  // Unary: !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const Expr *SubE = UO->getSubExpr()) {
        if (const MemRegion *MR = getTrackedRegionFromExpr(SubE, C, State))
          return MR;
      }
    }
  }

  // Truthiness: if (ptr)
  if (const MemRegion *MR = getTrackedRegionFromExpr(CondE, C, State))
    return MR;

  return nullptr;
}

const Expr *SAGenTestChecker::getDerefBaseExpr(const Stmt *S, CheckerContext &C) const {
  // Member access via pointer: ptr->field
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      return ME->getBase();
    }
  }
  // Explicit dereference: *ptr
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      return UO->getSubExpr();
    }
  }
  // Array subscript via pointer: ptr[i]
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    return ASE->getBase();
  }
  return nullptr;
}

// -------- Callbacks --------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Identify calls to known optional getters.
  if (isOptionalGetterExpr(OriginExpr, C)) {
    SVal Ret = Call.getReturnValue();
    if (SymbolRef Sym = Ret.getAsSymbol()) {
      ProgramStateRef State = C.getState();
      State = State->set<OptRetSymMap>(Sym, 1);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *Dst = Loc.getAsRegion();
  if (!Dst) return;
  Dst = Dst->getBaseRegion();
  if (!Dst) return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Case A: Binding the return of an optional getter (tagged by symbol).
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (State->get<OptRetSymMap>(Sym)) {
      State = overwriteFlags(State, Dst, FromOptionalGetter);
      State = State->remove<OptRetSymMap>(Sym);
      Changed = true;
    }
  }

  // Case B: Binding from another tracked region -> copy flags.
  if (!Changed) {
    if (const MemRegion *Src = Val.getAsRegion()) {
      Src = Src->getBaseRegion();
      if (Src) {
        if (const unsigned *SrcFlags = State->get<OptionalPtrMap>(Src)) {
          State = overwriteFlags(State, Dst, *SrcFlags);
          Changed = true;
        }
      }
    }
  }

  // Case C: Fallback - detect inline optional getter call on RHS syntactically.
  if (!Changed && S) {
    if (const auto *CE = findSpecificTypeInChildren<CallExpr>(S)) {
      if (isOptionalGetterExpr(CE, C)) {
        State = overwriteFlags(State, Dst, FromOptionalGetter);
        Changed = true;
      }
    }
  }

  // Any other assignment wipes prior tracking for Dst (fresh value not from optional getter).
  if (!Changed) {
    if (State->get<OptionalPtrMap>(Dst)) {
      State = State->remove<OptionalPtrMap>(Dst);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;

  ProgramStateRef State = C.getState();
  bool Updated = false;

  // First, handle IS_ERR_OR_NULL(ptr) and IS_ERR(ptr)
  if (const auto *CE = findSpecificTypeInChildren<CallExpr>(Condition)) {
    if (isIS_ERR_OR_NULL_Name(CE, C) || isIS_ERR_Name(CE, C)) {
      if (CE->getNumArgs() >= 1) {
        const Expr *Arg0 = CE->getArg(0);
        if (const MemRegion *MR = getTrackedRegionFromExpr(Arg0, C, State)) {
          if (isIS_ERR_OR_NULL_Name(CE, C)) {
            State = orFlags(State, MR, ErrCheckedObserved | NullCheckedObserved);
          } else if (isIS_ERR_Name(CE, C)) {
            State = orFlags(State, MR, ErrCheckedObserved);
          }
          Updated = true;
        }
      }
    }
  }

  // Then, detect explicit NULL-check shapes
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (CondE) {
    CondE = CondE->IgnoreParenCasts();

    // Binary: ptr == NULL or ptr != NULL
    if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
      if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
        const Expr *L = BO->getLHS()->IgnoreParenCasts();
        const Expr *R = BO->getRHS()->IgnoreParenCasts();
        bool LIsNull = L->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
        bool RIsNull = R->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
        const Expr *PtrE = nullptr;
        if (LIsNull && !RIsNull) PtrE = R;
        else if (RIsNull && !LIsNull) PtrE = L;
        if (PtrE) {
          if (const MemRegion *MR = getTrackedRegionFromExpr(PtrE, C, State)) {
            State = orFlags(State, MR, NullCheckedObserved);
            Updated = true;
          }
        }
      }
    }

    // Unary: !ptr
    if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
      if (UO->getOpcode() == UO_LNot) {
        if (const Expr *SubE = UO->getSubExpr()) {
          if (const MemRegion *MR = getTrackedRegionFromExpr(SubE, C, State)) {
            State = orFlags(State, MR, NullCheckedObserved);
            Updated = true;
          }
        }
      }
    }

    // Truthiness: if (ptr)
    if (const MemRegion *MR = getTrackedRegionFromExpr(CondE, C, State)) {
      // Heuristically treat as a NULL-check observation.
      State = orFlags(State, MR, NullCheckedObserved);
      Updated = true;
    }
  }

  if (Updated)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!S) return;

  const Expr *BaseE = getDerefBaseExpr(S, C);
  if (!BaseE) return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;

  const unsigned *Flags = State->get<OptionalPtrMap>(MR);
  if (!Flags) return;

  if ((*Flags & FromOptionalGetter) && !(*Flags & NullCheckedObserved)) {
    reportDerefWithoutNullCheck(S, *Flags, C);
  }
}

void SAGenTestChecker::reportDerefWithoutNullCheck(const Stmt *S, unsigned Flags, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  const char *Msg =
      (Flags & ErrCheckedObserved)
          ? "Missing NULL-check after IS_ERR() for optional resource"
          : "Dereference of optional resource without NULL-check";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of optional resources when only IS_ERR() is checked and NULL is not",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
