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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track pointer-like storage regions that may come from "optional" getters.
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion*, unsigned)
// Map the return symbol of optional getter calls; used to transfer tag on bind.
// Value encodes the OptionalOriginKind.
REGISTER_MAP_WITH_PROGRAMSTATE(OptRetSymMap, SymbolRef, unsigned)
// Track the origin kind for each tracked destination region (to validate type).
REGISTER_MAP_WITH_PROGRAMSTATE(OptOriginKindMap, const MemRegion*, unsigned)

namespace {

static constexpr unsigned FromOptionalGetter = 1u;   // bit0
static constexpr unsigned NullCheckedObserved = 2u;  // bit1
static constexpr unsigned ErrCheckedObserved  = 4u;  // bit2

enum OptionalOriginKind : unsigned {
  OK_None = 0,
  OK_GPIOD_ARRAY = 1, // e.g., devm_gpiod_get_array_optional
  OK_GPIOD_DESC  = 2  // e.g., devm_gpiod_get_optional
};

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
      static OptionalOriginKind optionalGetterKindForCall(const CallEvent &Call);

      static bool isIS_ERR_Name(const Expr *E, CheckerContext &C);
      static bool isIS_ERR_OR_NULL_Name(const Expr *E, CheckerContext &C);

      static ProgramStateRef overwriteFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Flags);
      static ProgramStateRef orFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Mask);

      // Get the tracked storage region (VarRegion/FieldRegion) for expression E, if any.
      const MemRegion *getTrackedRegionFromExpr(const Expr *E, CheckerContext &C,
                                                ProgramStateRef State) const;

      // AST helpers to determine dereference contexts.
      static bool nodeContains(const Stmt *Root, const Stmt *Query);
      const Stmt *findDerefUseSiteForLoad(const Stmt *S, CheckerContext &C) const;

      // Only track genuine storage locations that can hold the optional pointer.
      static bool isTrackableStorageRegion(const MemRegion *R);
      static bool isPointerLikeStorage(const MemRegion *R, CheckerContext &C);

      // Validate and suppress spurious reports.
      static bool isGPIODescLikeType(QualType QT);
      static bool isConsistentWithOriginKind(OptionalOriginKind K, QualType PtrQT);
      static const Expr *getPointerBaseExprFromDerefSite(const Stmt *DerefSite);

      bool isFalsePositive(const MemRegion *Reg, const Stmt *DerefSite, CheckerContext &C) const;

      void reportDerefWithoutNullCheck(const Stmt *S, unsigned Flags, CheckerContext &C) const;

      // New: Compute storage region for lvalue-like exprs (MemberExpr/DeclRefExpr).
      const MemRegion *computeStorageRegionForExpr(const Expr *E, CheckerContext &C) const;
};

// -------- Helpers --------

static bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

static StringRef getCalleeName(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName();
  return StringRef();
}

OptionalOriginKind SAGenTestChecker::optionalGetterKindForCall(const CallEvent &Call) {
  StringRef Name = getCalleeName(Call);
  if (Name.empty())
    return OK_None;

  // Precisely match well-known optional GPIO getters.
  if (Name.equals("devm_gpiod_get_array_optional") ||
      Name.equals("gpiod_get_array_optional"))
    return OK_GPIOD_ARRAY;

  if (Name.equals("devm_gpiod_get_optional") ||
      Name.equals("gpiod_get_optional"))
    return OK_GPIOD_DESC;

  return OK_None;
}

bool SAGenTestChecker::isIS_ERR_Name(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "IS_ERR", C);
}

bool SAGenTestChecker::isIS_ERR_OR_NULL_Name(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "IS_ERR_OR_NULL", C);
}

ProgramStateRef SAGenTestChecker::overwriteFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Flags) {
  if (!Reg) return State;
  return State->set<OptionalPtrMap>(Reg, Flags);
}

ProgramStateRef SAGenTestChecker::orFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Mask) {
  if (!Reg) return State;
  const unsigned *Old = State->get<OptionalPtrMap>(Reg);
  unsigned NewFlags = (Old ? *Old : 0u) | Mask;
  return State->set<OptionalPtrMap>(Reg, NewFlags);
}

// Compute the storage region (VarRegion/FieldRegion) for an expression E,
// when applicable. This is crucial to consistently match the same region
// we track in checkBind (the lvalue storage), rather than the pointee region
// or the rvalue symbol.
const MemRegion *SAGenTestChecker::computeStorageRegionForExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  E = E->IgnoreParenCasts();

  ProgramStateRef State = C.getState();

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    SVal LV = State->getSVal(ME, C.getLocationContext());
    return LV.getAsRegion();
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    SVal LV = State->getSVal(DRE, C.getLocationContext());
    return LV.getAsRegion();
  }

  // Fall back to what the expression evaluates to.
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

const MemRegion *SAGenTestChecker::getTrackedRegionFromExpr(const Expr *E, CheckerContext &C, ProgramStateRef State) const {
  if (!E) return nullptr;
  const MemRegion *MR = computeStorageRegionForExpr(E, C);
  if (MR && State->get<OptionalPtrMap>(MR))
    return MR;
  return nullptr;
}

bool SAGenTestChecker::nodeContains(const Stmt *Root, const Stmt *Query) {
  if (!Root || !Query) return false;
  if (Root == Query) return true;
  for (const Stmt *Child : Root->children()) {
    if (Child && nodeContains(Child, Query))
      return true;
  }
  return false;
}

// Find a dereference use site for a load represented by statement S:
// - MemberExpr with '->' where S is within the base subtree.
// - UnaryOperator '*' where S is within the subexpr subtree.
// - ArraySubscriptExpr where S is within the base subtree.
const Stmt *SAGenTestChecker::findDerefUseSiteForLoad(const Stmt *S, CheckerContext &C) const {
  if (!S) return nullptr;

  // Check parent MemberExpr with '->'
  if (const auto *ME = findSpecificTypeInParents<MemberExpr>(S, C)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (Base && nodeContains(Base, S))
        return ME;
    }
  }

  // Check parent UnaryOperator '*'
  if (const auto *UO = findSpecificTypeInParents<UnaryOperator>(S, C)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr();
      if (Sub && nodeContains(Sub, S))
        return UO;
    }
  }

  // Check parent ArraySubscriptExpr
  if (const auto *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(S, C)) {
    const Expr *Base = ASE->getBase();
    if (Base && nodeContains(Base, S))
      return ASE;
  }

  return nullptr;
}

bool SAGenTestChecker::isTrackableStorageRegion(const MemRegion *R) {
  // Only track storage locations that represent real lvalues: fields or local/global vars.
  return isa<FieldRegion>(R) || isa<VarRegion>(R);
}

bool SAGenTestChecker::isPointerLikeStorage(const MemRegion *R, CheckerContext &C) {
  if (!R) return false;
  QualType T;
  if (const auto *FR = dyn_cast<FieldRegion>(R))
    T = FR->getDecl()->getType();
  else if (const auto *VR = dyn_cast<VarRegion>(R))
    T = VR->getValueType();
  else
    return false;

  return !T.isNull() && T->isPointerType();
}

bool SAGenTestChecker::isGPIODescLikeType(QualType QT) {
  if (QT.isNull())
    return false;
  if (!QT->isPointerType())
    return false;

  QualType Pointee = QT->getPointeeType();
  if (const RecordType *RT = Pointee->getAs<RecordType>()) {
    if (const RecordDecl *RD = RT->getDecl()) {
      StringRef Name = RD->getName();
      // Typical Linux types: 'gpio_desc' (single) and 'gpio_descs' (array).
      return Name.contains_insensitive("gpio_desc");
    }
  }

  // Fallback: textual check, safer than nothing
  std::string S = Pointee.getAsString();
  return StringRef(S).contains_insensitive("gpio_desc");
}

bool SAGenTestChecker::isConsistentWithOriginKind(OptionalOriginKind K, QualType PtrQT) {
  if (K == OK_None)
    return false; // must have known origin

  if (!PtrQT->isPointerType())
    return false;

  // For now both GPIOD kinds point to gpio_desc or gpio_descs.
  // If more origins are added, refine here.
  return isGPIODescLikeType(PtrQT);
}

const Expr *SAGenTestChecker::getPointerBaseExprFromDerefSite(const Stmt *DerefSite) {
  if (!DerefSite) return nullptr;

  if (const auto *ME = dyn_cast<MemberExpr>(DerefSite)) {
    if (ME->isArrow())
      return ME->getBase()->IgnoreParenCasts();
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(DerefSite)) {
    if (UO->getOpcode() == UO_Deref)
      return UO->getSubExpr()->IgnoreParenCasts();
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(DerefSite)) {
    return ASE->getBase()->IgnoreParenCasts();
  }
  return nullptr;
}

bool SAGenTestChecker::isFalsePositive(const MemRegion *Reg, const Stmt *DerefSite, CheckerContext &C) const {
  if (!Reg || !DerefSite)
    return true;

  ProgramStateRef State = C.getState();
  const unsigned *Flags = State->get<OptionalPtrMap>(Reg);
  if (!Flags || !(*Flags & FromOptionalGetter))
    return true;

  const unsigned *KPtr = State->get<OptOriginKindMap>(Reg);
  OptionalOriginKind K = KPtr ? static_cast<OptionalOriginKind>(*KPtr) : OK_None;
  if (K == OK_None)
    return true;

  // Validate that the dereferenced expression is of a type consistent with origin.
  const Expr *BaseE = getPointerBaseExprFromDerefSite(DerefSite);
  if (!BaseE)
    return true; // Not a dereference site we can reason about

  QualType QT = BaseE->getType();
  if (QT.isNull())
    return true;

  if (!isConsistentWithOriginKind(K, QT))
    return true;

  return false;
}

// -------- Callbacks --------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Identify calls to known optional getters.
  OptionalOriginKind K = optionalGetterKindForCall(Call);
  if (K == OK_None)
    return;

  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    ProgramStateRef State = C.getState();
    State = State->set<OptRetSymMap>(Sym, static_cast<unsigned>(K));
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *Dst = Loc.getAsRegion();
  if (!Dst) return;
  if (!isTrackableStorageRegion(Dst)) return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Case A: Binding the return of an optional getter (tagged by symbol) into storage.
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (const unsigned *KPtr = State->get<OptRetSymMap>(Sym)) {
      OptionalOriginKind K = static_cast<OptionalOriginKind>(*KPtr);
      // Only track pointer-typed storage.
      if (isPointerLikeStorage(Dst, C)) {
        State = overwriteFlags(State, Dst, FromOptionalGetter);
        State = State->set<OptOriginKindMap>(Dst, static_cast<unsigned>(K));
        Changed = true;
      }
      State = State->remove<OptRetSymMap>(Sym);
    }
  }

  // Case B: Binding from another tracked storage region -> copy flags and origin kind.
  if (!Changed) {
    if (const MemRegion *Src = Val.getAsRegion()) {
      if (State->get<OptionalPtrMap>(Src)) {
        const unsigned *SrcFlags = State->get<OptionalPtrMap>(Src);
        State = overwriteFlags(State, Dst, *SrcFlags);
        if (const unsigned *SrcK = State->get<OptOriginKindMap>(Src))
          State = State->set<OptOriginKindMap>(Dst, *SrcK);
        Changed = true;
      } else {
        // If destination was previously tracked but now overwritten with an unrelated value,
        // clear tracking to avoid stale flags.
        if (State->get<OptionalPtrMap>(Dst) || State->get<OptOriginKindMap>(Dst)) {
          State = State->remove<OptionalPtrMap>(Dst);
          State = State->remove<OptOriginKindMap>(Dst);
          Changed = true;
        }
      }
    }
  }

  // Any other assignment wipes prior tracking for Dst (fresh value not from optional getter).
  if (!Changed) {
    if (State->get<OptionalPtrMap>(Dst) || State->get<OptOriginKindMap>(Dst)) {
      State = State->remove<OptionalPtrMap>(Dst);
      State = State->remove<OptOriginKindMap>(Dst);
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
      State = orFlags(State, MR, NullCheckedObserved);
      Updated = true;
    }
  }

  if (Updated)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // We only care about loads from optional pointer storage, and only when used
  // as a base of a dereference like '->', '*', or '[]'.
  if (!IsLoad || !S) return;

  ProgramStateRef State = C.getState();
  const MemRegion *LocReg = Loc.getAsRegion();
  if (!LocReg) return;
  if (!isTrackableStorageRegion(LocReg)) return;

  const unsigned *Flags = State->get<OptionalPtrMap>(LocReg);
  if (!Flags) return;

  // Is this particular load used in a dereference context?
  const Stmt *DerefSite = findDerefUseSiteForLoad(S, C);
  if (!DerefSite) return;

  // Suppress if provenance/type validation fails.
  if (isFalsePositive(LocReg, DerefSite, C))
    return;

  if ((*Flags & FromOptionalGetter) && !(*Flags & NullCheckedObserved)) {
    reportDerefWithoutNullCheck(DerefSite, *Flags, C);
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
