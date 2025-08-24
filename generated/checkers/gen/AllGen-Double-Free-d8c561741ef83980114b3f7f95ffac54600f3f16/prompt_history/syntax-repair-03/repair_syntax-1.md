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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track resource phases and dataflow between set_ready return and err variable.
REGISTER_MAP_WITH_PROGRAMSTATE(ResourcePhaseMap, const MemRegion*, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(SetReadyRetSymToRegionMap, SymbolRef, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToResourceMap, const MemRegion*, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(AttemptedSetReadyRegions, const MemRegion*)

namespace {

enum PhaseBits : unsigned {
  PHASE_NONE    = 0,
  PHASE_CREATED = 1u << 0,
  PHASE_READY   = 1u << 1
};

class SAGenTestChecker : public Checker<
                            check::PostCall,
                            check::PreCall,
                            check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Wrong close in error path (double free risk)", "Memory Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers for function identification
      static bool isCreateSQ(const CallEvent &Call, CheckerContext &C);
      static bool isSetSqRdy(const CallEvent &Call, CheckerContext &C);
      static bool isCloseSQ(const CallEvent &Call, CheckerContext &C);

      // Extractors for sq MemRegion from calls
      static const MemRegion* getSqRegionFromCreate(const CallEvent &Call, CheckerContext &C);
      static const MemRegion* getSqRegionFromSetRdy(const CallEvent &Call, CheckerContext &C);
      static const MemRegion* getSqRegionFromClose(const CallEvent &Call, CheckerContext &C);

      // Extract error variable region from if condition
      static const MemRegion* getErrVarRegionFromIfCond(const IfStmt *IfS, CheckerContext &C);

      void reportWrongClose(const CallEvent &Call, CheckerContext &C) const;
};

// ==== Helper implementations ====

bool SAGenTestChecker::isCreateSQ(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "hws_send_ring_create_sq", C);
}

bool SAGenTestChecker::isSetSqRdy(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "hws_send_ring_set_sq_rdy", C);
}

bool SAGenTestChecker::isCloseSQ(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "hws_send_ring_close_sq", C);
}

const MemRegion* SAGenTestChecker::getSqRegionFromCreate(const CallEvent &Call, CheckerContext &C) {
  if (Call.getNumArgs() <= 4)
    return nullptr;
  const Expr *Arg = Call.getArgExpr(4);
  if (!Arg) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(Arg, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::getSqRegionFromSetRdy(const CallEvent &Call, CheckerContext &C) {
  if (Call.getNumArgs() <= 1)
    return nullptr;

  const Expr *Arg = Call.getArgExpr(1);
  if (!Arg) return nullptr;

  // Expect pattern: sq->sqn; extract "sq"
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg);
  if (!ME) return nullptr;

  const Expr *Base = ME->getBase();
  if (!Base) return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(Base, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::getSqRegionFromClose(const CallEvent &Call, CheckerContext &C) {
  if (Call.getNumArgs() == 0)
    return nullptr;
  const Expr *Arg = Call.getArgExpr(0);
  if (!Arg) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(Arg, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::getErrVarRegionFromIfCond(const IfStmt *IfS, CheckerContext &C) {
  if (!IfS) return nullptr;
  const Expr *Cond = IfS->getCond();
  if (!Cond) return nullptr;

  // Find a DeclRefExpr within the condition (e.g., "if (err)" or "if (err != 0)")
  const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Cond);
  if (!DRE) return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(DRE, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

// ==== Checker callbacks ====

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track creation phase
  if (isCreateSQ(Call, C)) {
    const MemRegion *SqReg = getSqRegionFromCreate(Call, C);
    if (!SqReg)
      return;
    unsigned Phase = PHASE_NONE;
    if (const unsigned *Old = State->get<ResourcePhaseMap>(SqReg))
      Phase = *Old;
    Phase |= PHASE_CREATED;
    State = State->set<ResourcePhaseMap>(SqReg, Phase);
    C.addTransition(State);
    return;
  }

  // Track set ready attempt and return symbol
  if (isSetSqRdy(Call, C)) {
    const MemRegion *SqReg = getSqRegionFromSetRdy(Call, C);
    if (SqReg) {
      State = State->add<AttemptedSetReadyRegions>(SqReg);
      // Map return symbol (err-like) to the sq region
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (RetSym) {
        State = State->set<SetReadyRetSymToRegionMap>(RetSym, SqReg);
      }
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Only handle cases where RHS is a symbol that we tracked from set_sq_rdy
  SymbolRef Sym = Val.getAsSymbol();
  if (!Sym)
    return;

  const MemRegion *ResReg = State->get<SetReadyRetSymToRegionMap>(Sym);
  if (!ResReg)
    return;

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // Associate the LHS variable (err-like) with the resource region
  State = State->set<ErrVarToResourceMap>(LHSReg, ResReg);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCloseSQ(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *SqReg = getSqRegionFromClose(Call, C);
  if (!SqReg)
    return;

  // Must have attempted to set ready for this resource
  if (!State->contains<AttemptedSetReadyRegions>(SqReg))
    return;

  // The resource should be in CREATED and not READY
  const unsigned *PhasePtr = State->get<ResourcePhaseMap>(SqReg);
  if (!PhasePtr)
    return;

  unsigned Phase = *PhasePtr;
  if (!(Phase & PHASE_CREATED) || (Phase & PHASE_READY))
    return;

  // Find the surrounding if-statement guarding this close
  const Expr *Orig = Call.getOriginExpr();
  if (!Orig)
    return;

  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Orig, C);
  if (!IfS)
    return;

  const MemRegion *ErrReg = getErrVarRegionFromIfCond(IfS, C);
  if (!ErrReg)
    return;

  const MemRegion *MappedRes = State->get<ErrVarToResourceMap>(ErrReg);
  if (!MappedRes)
    return;

  if (MappedRes != SqReg)
    return;

  // All conditions met: report problem
  reportWrongClose(Call, C);
}

void SAGenTestChecker::reportWrongClose(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "hws_send_ring_close_sq in set_sq_rdy error path; call mlx5_core_destroy_sq instead (double free risk)", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects hws_send_ring_close_sq in set_sq_rdy error path; use destroy_sq to avoid double free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 183 |   const MemRegion *ResReg = State->get<SetReadyRetSymToRegionMap>(Sym);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::SymExpr*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization

- Error Line: 234 |   const MemRegion *MappedRes = State->get<ErrVarToResourceMap>(ErrReg);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
