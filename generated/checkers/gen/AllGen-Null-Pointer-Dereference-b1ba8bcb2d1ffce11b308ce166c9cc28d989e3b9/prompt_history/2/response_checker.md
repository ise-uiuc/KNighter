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
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program state customizations ----------------
REGISTER_SET_WITH_PROGRAMSTATE(OptionalRetSyms, SymbolRef)
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRetSymOrigin, SymbolRef, const Stmt*)
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRegionChecked, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRegionOrigin, const MemRegion*, const Stmt*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::Bind,
    check::BranchCondition,
    check::Location
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unchecked dereference of optional resource", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      static bool isOptionalGetter(const CallEvent &Call, CheckerContext &C);
      static bool isNullExpr(const Expr *E, CheckerContext &C);
      void markRegionCheckedForExpr(const Expr *E, CheckerContext &C) const;
      void reportUncheckedDeref(const Stmt *DerefSite, const MemRegion *BaseReg,
                                CheckerContext &C) const;
};

bool SAGenTestChecker::isOptionalGetter(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Tight allowlist of optional getters that legitimately return NULL if absent.
  if (ExprHasName(OE, "devm_gpiod_get_array_optional", C)) return true;
  if (ExprHasName(OE, "devm_gpiod_get_optional", C)) return true;
  if (ExprHasName(OE, "gpiod_get_optional", C)) return true;

  return false;
}

bool SAGenTestChecker::isNullExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return E->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNull);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isOptionalGetter(Call, C))
    return;

  ProgramStateRef State = C.getState();

  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  // Tag this return symbol as optional (may be NULL).
  State = State->add<OptionalRetSyms>(Sym);

  // Remember origin call stmt for diagnostics.
  if (const Stmt *S = Call.getOriginExpr())
    State = State->set<OptionalRetSymOrigin>(Sym, S);

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstR = Loc.getAsRegion();
  if (!DstR)
    return;
  DstR = DstR->getBaseRegion();
  if (!DstR)
    return;

  bool DidUpdate = false;

  // Case 1: Binding from a return symbol of an optional getter.
  if (SymbolRef RHSym = Val.getAsSymbol()) {
    if (State->contains<OptionalRetSyms>(RHSym)) {
      State = State->set<OptionalRegionChecked>(DstR, false);
      if (const Stmt *Orig = State->get<OptionalRetSymOrigin>(RHSym)) {
        State = State->set<OptionalRegionOrigin>(DstR, Orig);
      }
      DidUpdate = true;
    }
  }

  // Case 2: Propagate tag between regions on plain assignment/aliasing.
  if (!DidUpdate) {
    if (const MemRegion *SrcR = Val.getAsRegion()) {
      SrcR = SrcR->getBaseRegion();
      if (SrcR) {
        if (const bool *Checked = State->get<OptionalRegionChecked>(SrcR)) {
          State = State->set<OptionalRegionChecked>(DstR, *Checked);
          if (const Stmt *Orig = State->get<OptionalRegionOrigin>(SrcR))
            State = State->set<OptionalRegionOrigin>(DstR, Orig);
          DidUpdate = true;
        }
      }
    }
  }

  if (DidUpdate)
    C.addTransition(State);
}

void SAGenTestChecker::markRegionCheckedForExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return;

  ProgramStateRef State = C.getState();

  // Map expression to region.
  const MemRegion *R = getMemRegionFromExpr(E, C);
  if (!R)
    return;

  R = R->getBaseRegion();
  if (!R)
    return;

  if (const bool *Tracked = State->get<OptionalRegionChecked>(R)) {
    if (!*Tracked) {
      State = State->set<OptionalRegionChecked>(R, true);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  // Pattern 1: if (!ptr) or multiple logical nots; still consider it a check.
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      if (Sub) {
        markRegionCheckedForExpr(Sub, C);
      }
      return;
    }
  }

  // Pattern 2: if (ptr == NULL) or if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS();
      const Expr *R = BO->getRHS();
      const Expr *PtrExpr = nullptr;

      bool LIsNull = isNullExpr(L, C);
      bool RIsNull = isNullExpr(R, C);
      if (LIsNull && !RIsNull)
        PtrExpr = R;
      else if (RIsNull && !LIsNull)
        PtrExpr = L;

      if (PtrExpr) {
        markRegionCheckedForExpr(PtrExpr, C);
      }
      return;
    }
  }

  // Pattern 3: if (ptr)
  // Treat any direct pointer-as-condition as a check.
  markRegionCheckedForExpr(CondE, C);
}

void SAGenTestChecker::reportUncheckedDeref(const Stmt *DerefSite,
                                            const MemRegion *BaseReg,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Optional resource may be NULL; dereferenced without NULL check", N);

  if (DerefSite)
    Rpt->addRange(DerefSite->getSourceRange());

  if (BaseReg) {
    ProgramStateRef State = C.getState();
    if (const Stmt *Origin = State->get<OptionalRegionOrigin>(BaseReg)) {
      PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(Origin, C.getSourceManager(), N->getLocationContext());
      Rpt->addNote("Optional getter can return NULL here", Loc, C.getSourceManager());
    }
  }

  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad || !S)
    return;

  ProgramStateRef State = C.getState();

  // Helper lambda to check base expression's region for being tracked and unchecked.
  auto CheckBaseExpr = [&](const Expr *BaseE) {
    if (!BaseE) return;
    const MemRegion *R = getMemRegionFromExpr(BaseE, C);
    if (!R) return;
    R = R->getBaseRegion();
    if (!R) return;

    const bool *Checked = State->get<OptionalRegionChecked>(R);
    if (Checked && *Checked == false) {
      reportUncheckedDeref(S, R, C);
    }
  };

  // Detect ptr->field
  if (const auto *ME = findSpecificTypeInParents<MemberExpr>(S, C)) {
    if (ME->isArrow()) {
      CheckBaseExpr(ME->getBase());
      return;
    }
  }

  // Detect ptr[i]
  if (const auto *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(S, C)) {
    CheckBaseExpr(ASE->getBase());
    return;
  }

  // Detect *ptr
  if (const auto *UO = findSpecificTypeInParents<UnaryOperator>(S, C)) {
    if (UO->getOpcode() == UO_Deref) {
      CheckBaseExpr(UO->getSubExpr());
      return;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked dereference when using *_get_optional() APIs that may return NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
