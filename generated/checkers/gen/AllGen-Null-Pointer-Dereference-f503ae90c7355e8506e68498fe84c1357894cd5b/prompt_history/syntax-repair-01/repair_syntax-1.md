## Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

## Instruction

The following checker fails to compile, and your task is to resolve the compilation error based on the provided error messages.

Here are some potential ways to fix the issue:

1. Use the correct API: The current API may not exist, or the class has no such member. Replace it with an appropriate one.

2. Use correct arguments: Ensure the arguments passed to the API have the correct types and the correct number.

3. Change the variable types: Adjust the types of some variables based on the error messages.

4. Be careful if you want to include a header file. Please make sure the header file exists. For instance "fatal error: clang/StaticAnalyzer/Core/PathDiagnostic.h: No such file or directory".

**The version of Clang environment is Clang-18. You should consider the API compatibility.**

**Please only repair the failed parts and keep the original semantics.**
**Please return the whole checker code after fixing the compilation error.**

## Suggestions

1. Please only use two types of bug reports:
  - BasicBugReport (const BugType &bt, StringRef desc, PathDiagnosticLocation l)
  - PathSensitiveBugReport (const BugType &bt, StringRef desc, const ExplodedNode *errorNode)
  - PathSensitiveBugReport (const BugType &bt, StringRef shortDesc, StringRef desc, const ExplodedNode *errorNode)

## Example

- Error Line: 48 |   Optional<DefinedOrUnknownSVal> SizeSVal;

  - Error Messages: ‘Optional’ was not declared in this scope; did you mean ‘clang::ObjCImplementationControl::Optional’?

  - Fix: Replace 'Optional<DefinedOrUnknownSVal>' with 'std::optional<DefinedOrUnknownSVal>', and include the appropriate header.

- Error Line: 113 |     const MemRegion *MR = Entry.first;

    - Error Messages: unused variable ‘MR’ [-Wunused-variable]

    - Fix: Remove the variable 'MR' if it is not used.

## Checker

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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(RiskySyms, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(RiskyRegions, const MemRegion*)

namespace {
class SAGenTestChecker
    : public Checker<
          check::PostCall,
          check::Bind,
          check::Location,
          check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Capability NULL dereference", "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  bool isCapabilityHelper(const CallEvent &Call, CheckerContext &C) const;
  const Expr *baseExprOfDeref(const Stmt *S) const;
  bool exprIsRiskyPtr(const Expr *E, CheckerContext &C) const;
  bool ptrMayBeNull(const Expr *E, CheckerContext &C) const;

  void reportPossibleNullDeref(const Stmt *S, StringRef Msg,
                               CheckerContext &C) const;
  bool regionDerivedFromRiskySym(const MemRegion *R, ProgramStateRef State) const;
};

bool SAGenTestChecker::isCapabilityHelper(const CallEvent &Call,
                                          CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Target helper(s)
  if (ExprHasName(Origin, "mt76_connac_get_he_phy_cap", C))
    return true;
  return false;
}

bool SAGenTestChecker::regionDerivedFromRiskySym(const MemRegion *R,
                                                 ProgramStateRef State) const {
  if (!R)
    return false;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return false;

  if (const auto *SR = dyn_cast<SymbolicRegion>(Base)) {
    SymbolRef Sym = SR->getSymbol();
    if (Sym && State->contains<RiskySyms>(Sym))
      return true;
  }
  return false;
}

const Expr *SAGenTestChecker::baseExprOfDeref(const Stmt *S) const {
  if (!S)
    return nullptr;

  // Direct pointer dereference: *ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref)
      return UO->getSubExpr()->IgnoreParenCasts();
  }

  // Member access through pointer: ptr->field
  if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    if (ME->isArrow())
      return ME->getBase()->IgnoreParenCasts();
  }

  // Array subscript: ptr[i] or (ptr->field)[i]
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    const Expr *B = ASE->getBase()->IgnoreParenCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(B)) {
      if (ME->isArrow())
        return ME->getBase()->IgnoreParenCasts();
      // If it's '.', it does not imply pointer deref (not our target).
    }
    // Otherwise, if B is a pointer expression, the base pointer is B itself.
    return B;
  }

  return nullptr;
}

bool SAGenTestChecker::exprIsRiskyPtr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // Check symbol
  SVal SV = State->getSVal(E, LCtx);
  if (SymbolRef Sym = SV.getAsSymbol()) {
    if (State->contains<RiskySyms>(Sym))
      return true;
  }

  // Check region membership or derivation
  if (const MemRegion *MR = SV.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (MR) {
      if (State->contains<RiskyRegions>(MR))
        return true;
      if (regionDerivedFromRiskySym(MR, State))
        return true;
    }
  } else {
    // Try direct region retrieval from expression
    if (const MemRegion *MR2 = getMemRegionFromExpr(E, C)) {
      MR2 = MR2->getBaseRegion();
      if (MR2) {
        if (State->contains<RiskyRegions>(MR2))
          return true;
        if (regionDerivedFromRiskySym(MR2, State))
          return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::ptrMayBeNull(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  SVal SV = State->getSVal(E, LCtx);
  if (SV.isUnknownOrUndef())
    return true; // conservatively, unknown could be NULL

  // Use assume on the boolean interpretation of the pointer (NULL => false)
  Optional<DefinedOrUnknownSVal> DUV = SV.getAs<DefinedOrUnknownSVal>();
  if (!DUV)
    return true;

  ProgramStateRef NullState = State->assume(*DUV, /*Assumption=*/false);
  return (bool)NullState;
}

void SAGenTestChecker::reportPossibleNullDeref(const Stmt *S, StringRef Msg,
                                               CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isCapabilityHelper(Call, C))
    return;

  ProgramStateRef State = C.getState();
  // Mark the returned symbol as risky (may be NULL)
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->add<RiskySyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  if (!LHS)
    return;

  bool RHSIsRisky = false;

  // Case 1: RHS carries risky symbol
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (State->contains<RiskySyms>(Sym))
      RHSIsRisky = true;
  }

  // Case 2: RHS region is risky directly
  if (!RHSIsRisky) {
    if (const MemRegion *RHSR = Val.getAsRegion()) {
      RHSR = RHSR->getBaseRegion();
      if (RHSR) {
        if (State->contains<RiskyRegions>(RHSR))
          RHSIsRisky = true;
        else if (regionDerivedFromRiskySym(RHSR, State))
          RHSIsRisky = true;
      }
    }
  }

  if (RHSIsRisky) {
    State = State->add<RiskyRegions>(LHS);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad || !S)
    return;

  const Expr *BaseE = baseExprOfDeref(S);
  if (!BaseE)
    return;

  if (!exprIsRiskyPtr(BaseE, C))
    return;

  if (ptrMayBeNull(BaseE, C)) {
    reportPossibleNullDeref(S, "Possible NULL dereference of capability pointer",
                            C);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;
    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    if (!exprIsRiskyPtr(ArgE, C))
      continue;

    if (ptrMayBeNull(ArgE, C)) {
      const Expr *Origin = Call.getOriginExpr();
      if (Origin) {
        reportPossibleNullDeref(
            Origin,
            "Possible NULL dereference of capability pointer passed to function",
            C);
      } else {
        reportPossibleNullDeref(
            ArgE,
            "Possible NULL dereference of capability pointer passed to function",
            C);
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Warns on dereferencing capability pointers that may be NULL (e.g., mt76_connac_get_he_phy_cap) without a NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 167 |   Optional<DefinedOrUnknownSVal> DUV = SV.getAs<DefinedOrUnknownSVal>();

	- Error Messages: ‘Optional’ was not declared in this scope; did you mean ‘clang::ObjCImplementationControl::Optional’?

- Error Line: 167 |   Optional<DefinedOrUnknownSVal> DUV = SV.getAs<DefinedOrUnknownSVal>();

	- Error Messages: xpected primary-expression before ‘>’ token

- Error Line: 167 |   Optional<DefinedOrUnknownSVal> DUV = SV.getAs<DefinedOrUnknownSVal>();

	- Error Messages: ‘DUV’ was not declared in this scope



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
