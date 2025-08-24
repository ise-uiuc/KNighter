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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/AST/Expr.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state customizations
using FieldSetTy = llvm::SmallVector<const FieldDecl *, 4>;
REGISTER_MAP_WITH_PROGRAMSTATE(ManualFreedMap, const MemRegion *, FieldSetTy)
REGISTER_MAP_WITH_PROGRAMSTATE(CleanupFreedMap, const MemRegion *, FieldSetTy)
REGISTER_MAP_WITH_PROGRAMSTATE(VarAliasBaseMap, const MemRegion *, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(VarAliasFieldMap, const MemRegion *, const FieldDecl *)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free of struct member", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      struct CleanupSpec {
        StringRef Name;
        unsigned ParamIndex;
        llvm::SmallVector<StringRef, 4> FieldNames;
      };

      // Predicates/utilities
      bool isFreeLike(const CallEvent &Call, CheckerContext &C) const;
      bool isKnownCleanup(const CallEvent &Call, CheckerContext &C, CleanupSpec &Out) const;

      bool getBaseAndFieldFromExpr(const Expr *E, CheckerContext &C,
                                   const MemRegion* &OutBase,
                                   const FieldDecl* &OutField) const;

      const FieldDecl *getFieldDeclByNameFromArg(const Expr *Arg,
                                                 StringRef FieldName,
                                                 CheckerContext &C) const;

      template <typename MapTrait>
      ProgramStateRef addFieldToMap(ProgramStateRef State, const MemRegion *Base,
                                    const FieldDecl *FD) const {
        FieldSetTy Set;
        if (const FieldSetTy *Existing = State->get<MapTrait>(Base))
          Set = *Existing;

        bool Found = false;
        for (const FieldDecl *EFD : Set) {
          if (EFD == FD) {
            Found = true;
            break;
          }
        }
        if (!Found)
          Set.push_back(FD);

        return State->set<MapTrait>(Base, Set);
      }

      template <typename MapTrait>
      bool containsField(ProgramStateRef State, const MemRegion *Base,
                         const FieldDecl *FD) const {
        if (!Base || !FD) return false;
        if (const FieldSetTy *Set = State->get<MapTrait>(Base)) {
          for (const FieldDecl *EFD : *Set) {
            if (EFD == FD)
              return true;
          }
        }
        return false;
      }

      void clearAliasFor(ProgramStateRef &State, const MemRegion *VarReg) const {
        if (!VarReg) return;
        State = State->remove<VarAliasBaseMap>(VarReg);
        State = State->remove<VarAliasFieldMap>(VarReg);
      }

      void reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                            StringRef Msg) const;
};

bool SAGenTestChecker::isFreeLike(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Use ExprHasName as suggested for name checking.
  if (ExprHasName(Origin, "kfree", C)) return true;
  if (ExprHasName(Origin, "kvfree", C)) return true;
  if (ExprHasName(Origin, "vfree", C)) return true;
  return false;
}

bool SAGenTestChecker::isKnownCleanup(const CallEvent &Call, CheckerContext &C,
                                      CleanupSpec &Out) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Currently known cleanup: bch2_dev_buckets_free(ca) frees ca->buckets_nouse.
  if (ExprHasName(Origin, "bch2_dev_buckets_free", C)) {
    Out.Name = "bch2_dev_buckets_free";
    Out.ParamIndex = 0;
    Out.FieldNames.clear();
    Out.FieldNames.push_back("buckets_nouse");
    return true;
  }

  return false;
}

const FieldDecl *SAGenTestChecker::getFieldDeclByNameFromArg(const Expr *Arg,
                                                             StringRef FieldName,
                                                             CheckerContext &C) const {
  if (!Arg)
    return nullptr;

  QualType T = Arg->getType();
  if (const auto *PT = T->getAs<PointerType>()) {
    T = PT->getPointeeType();
  }
  const RecordType *RT = T->getAs<RecordType>();
  if (!RT)
    return nullptr;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return nullptr;

  RD = RD->getDefinition();
  if (!RD)
    return nullptr;

  for (const auto *FD : RD->fields()) {
    if (FD && FD->getName() == FieldName)
      return FD;
  }
  return nullptr;
}

bool SAGenTestChecker::getBaseAndFieldFromExpr(const Expr *E, CheckerContext &C,
                                               const MemRegion* &OutBase,
                                               const FieldDecl* &OutField) const {
  OutBase = nullptr;
  OutField = nullptr;
  if (!E)
    return false;

  // Case 1: Direct member expression like ca->field
  const Stmt *S = E->IgnoreParenImpCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    const ValueDecl *VD = ME->getMemberDecl();
    const FieldDecl *FD = dyn_cast<FieldDecl>(VD);
    if (!FD)
      return false;

    const Expr *BaseExpr = ME->getBase();
    if (!BaseExpr)
      return false;

    const MemRegion *BaseReg = getMemRegionFromExpr(BaseExpr, C);
    if (!BaseReg)
      return false;
    BaseReg = BaseReg->getBaseRegion();

    OutBase = BaseReg;
    OutField = FD;
    return true;
  }

  // Case 2: Variable that aliases a member pointer.
  const MemRegion *VarReg = getMemRegionFromExpr(E, C);
  if (VarReg) {
    VarReg = VarReg->getBaseRegion();
    ProgramStateRef State = C.getState();
    if (const MemRegion *const *AliasedBasePtr =
            State->get<VarAliasBaseMap>(VarReg)) {
      if (const FieldDecl *const *AliasedFieldPtr =
              State->get<VarAliasFieldMap>(VarReg)) {
        OutBase = (*AliasedBasePtr)->getBaseRegion();
        OutField = *AliasedFieldPtr;
        return true;
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                                        StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Handle manual free-like calls first.
  if (isFreeLike(Call, C)) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *Arg = Call.getArgExpr(0);
    const MemRegion *BaseReg = nullptr;
    const FieldDecl *FD = nullptr;

    if (!getBaseAndFieldFromExpr(Arg, C, BaseReg, FD)) {
      // Try a backup using regions from the argument value if available.
      if (const MemRegion *MR = Call.getArgSVal(0).getAsRegion()) {
        if (const auto *FR = dyn_cast<FieldRegion>(MR)) {
          BaseReg = FR->getSuperRegion();
          if (BaseReg) BaseReg = BaseReg->getBaseRegion();
          FD = FR->getDecl();
        }
      }
    }

    if (!BaseReg || !FD)
      return;

    // If already known as freed by cleanup, warn now.
    if (containsField<CleanupFreedMap>(State, BaseReg, FD)) {
      reportDoubleFree(Call, C, "Double free: member also freed by cleanup helper");
      return;
    }

    // Record as manually freed.
    State = addFieldToMap<ManualFreedMap>(State, BaseReg, FD);
    C.addTransition(State);
    return;
  }

  // Handle known cleanup helpers.
  CleanupSpec Spec;
  if (isKnownCleanup(Call, C, Spec)) {
    if (Call.getNumArgs() <= Spec.ParamIndex)
      return;

    const Expr *ObjArg = Call.getArgExpr(Spec.ParamIndex);
    const MemRegion *BaseReg = getMemRegionFromExpr(ObjArg, C);
    if (!BaseReg)
      return;
    BaseReg = BaseReg->getBaseRegion();

    for (StringRef FieldName : Spec.FieldNames) {
      const FieldDecl *FD = getFieldDeclByNameFromArg(ObjArg, FieldName, C);
      if (!FD)
        continue;

      if (containsField<ManualFreedMap>(State, BaseReg, FD)) {
        reportDoubleFree(Call, C, "Double free: member already freed earlier");
      }

      State = addFieldToMap<CleanupFreedMap>(State, BaseReg, FD);
    }
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const MemRegion *AliasedBase = nullptr;
  const FieldDecl *AliasedField = nullptr;

  // Try to derive alias from RHS expression when available.
  const Expr *RHSExpr = nullptr;
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      RHSExpr = BO->getRHS();
  } else if (const auto *DS = dyn_cast_or_null<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast_or_null<VarDecl>(D)) {
        if (VD->hasInit())
          RHSExpr = VD->getInit();
      }
    }
  }

  bool FoundAlias = false;
  if (RHSExpr && getBaseAndFieldFromExpr(RHSExpr, C, AliasedBase, AliasedField)) {
    FoundAlias = true;
  } else {
    // Fallback: derive from Val region.
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      if (const auto *FR = dyn_cast<FieldRegion>(RHSReg)) {
        const MemRegion *Base = FR->getSuperRegion();
        if (Base) Base = Base->getBaseRegion();
        AliasedBase = Base;
        AliasedField = FR->getDecl();
        FoundAlias = (AliasedBase && AliasedField);
      } else {
        // Propagate existing alias info if RHS is another variable.
        RHSReg = RHSReg->getBaseRegion();
        if (const MemRegion *const *BasePtr =
                State->get<VarAliasBaseMap>(RHSReg)) {
          if (const FieldDecl *const *FDPtr =
                  State->get<VarAliasFieldMap>(RHSReg)) {
            AliasedBase = (*BasePtr)->getBaseRegion();
            AliasedField = *FDPtr;
            FoundAlias = true;
          }
        }
      }
    }
  }

  if (FoundAlias) {
    State = State->set<VarAliasBaseMap>(LHSReg, AliasedBase);
    State = State->set<VarAliasFieldMap>(LHSReg, AliasedField);
  } else {
    // Clear stale alias info if any.
    clearAliasFor(State, LHSReg);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when struct member is freed manually and again by cleanup helper",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
