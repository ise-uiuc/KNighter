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
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ResourceStateMap, const MemRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)

// Resource states
enum ResourceState : unsigned {
  RS_Unknown = 0,
  RS_Allocated = 1,
  RS_MaybeFreed = 2,
  RS_Freed = 3
};

namespace {
class SAGenTestChecker
    : public Checker<
          check::PreCall,
          check::PostCall,
          check::Bind,
          check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double free of resource", "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helpers for function identification
  bool isAllocCall(const CallEvent &Call, CheckerContext &C) const;
  bool isFreeCall(const CallEvent &Call, CheckerContext &C) const;
  bool isMaybeFreeCall(const CallEvent &Call, CheckerContext &C) const;

  // Alias helpers
  const MemRegion *getRootAlias(ProgramStateRef State, const MemRegion *R) const;
  ProgramStateRef setAlias(ProgramStateRef State, const MemRegion *Dst,
                           const MemRegion *SrcRoot) const;

  // Resource state helpers
  unsigned getResState(ProgramStateRef State, const MemRegion *R) const;
  ProgramStateRef setResState(ProgramStateRef State, const MemRegion *R,
                              unsigned NewState) const;

  // Utility to extract and canonicalize region from a call argument
  const MemRegion *getArgBaseRegion(const CallEvent &Call, unsigned Idx,
                                    CheckerContext &C) const;

  void reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                        const MemRegion *Root) const;
};

// ================== Helper Implementations ==================

bool SAGenTestChecker::isAllocCall(const CallEvent &Call,
                                   CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "fastrpc_buf_alloc", C) ||
         ExprHasName(E, "fastrpc_remote_heap_alloc", C);
}

bool SAGenTestChecker::isFreeCall(const CallEvent &Call,
                                  CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "fastrpc_buf_free", C);
}

bool SAGenTestChecker::isMaybeFreeCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "fastrpc_req_munmap_impl", C);
}

const MemRegion *SAGenTestChecker::getRootAlias(ProgramStateRef State,
                                                const MemRegion *R) const {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallSet<const MemRegion *, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second) // loop detected
      break;
    const MemRegion *Next = State->get<PtrAliasMap>(Cur);
    if (!Next)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur ? Cur->getBaseRegion() : nullptr;
}

ProgramStateRef SAGenTestChecker::setAlias(ProgramStateRef State,
                                           const MemRegion *Dst,
                                           const MemRegion *SrcRoot) const {
  if (!Dst || !SrcRoot)
    return State;
  const MemRegion *DstRoot = Dst->getBaseRegion();
  const MemRegion *SrcCanon = getRootAlias(State, SrcRoot);
  if (!DstRoot || !SrcCanon)
    return State;
  // Map destination root to source canonical root
  State = State->set<PtrAliasMap>(DstRoot, SrcCanon);
  return State;
}

unsigned SAGenTestChecker::getResState(ProgramStateRef State,
                                       const MemRegion *R) const {
  if (!R)
    return RS_Unknown;
  const MemRegion *Root = getRootAlias(State, R);
  if (!Root)
    return RS_Unknown;
  const unsigned *St = State->get<ResourceStateMap>(Root);
  return St ? *St : RS_Unknown;
}

ProgramStateRef SAGenTestChecker::setResState(ProgramStateRef State,
                                              const MemRegion *R,
                                              unsigned NewState) const {
  if (!R)
    return State;
  const MemRegion *Root = getRootAlias(State, R);
  if (!Root)
    Root = R->getBaseRegion();
  if (!Root)
    return State;
  return State->set<ResourceStateMap>(Root, NewState);
}

const MemRegion *SAGenTestChecker::getArgBaseRegion(const CallEvent &Call,
                                                    unsigned Idx,
                                                    CheckerContext &C) const {
  if (Idx >= Call.getNumArgs())
    return nullptr;
  const Expr *ArgE = Call.getArgExpr(Idx);
  if (!ArgE)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call,
                                        CheckerContext &C,
                                        const MemRegion *Root) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free: resource may have been released earlier in error path",
      N);
  R->addRange(Call.getSourceRange());
  if (Root)
    R->markInteresting(Root);
  C.emitReport(std::move(R));
}

// ================== Checker Callbacks ==================

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Warn before a second free happens.
  if (!isFreeCall(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getArgBaseRegion(Call, 0, C);
  if (!MR)
    return;

  const MemRegion *Root = getRootAlias(State, MR);
  if (!Root)
    Root = MR->getBaseRegion();

  unsigned St = getResState(State, Root);
  if (St == RS_MaybeFreed || St == RS_Freed) {
    reportDoubleFree(Call, C, Root);
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Model allocation: out-param at index 3 -> Allocated
  if (isAllocCall(Call, C)) {
    const MemRegion *OutMR = getArgBaseRegion(Call, 3, C);
    if (OutMR) {
      const MemRegion *Root = getRootAlias(State, OutMR);
      if (!Root)
        Root = OutMR->getBaseRegion();
      if (Root) {
        State = State->set<ResourceStateMap>(Root, RS_Allocated);
        C.addTransition(State);
      }
    }
    return;
  }

  // Model maybe-free helper: arg1 -> MaybeFreed
  if (isMaybeFreeCall(Call, C)) {
    const MemRegion *ArgMR = getArgBaseRegion(Call, 1, C);
    if (ArgMR) {
      const MemRegion *Root = getRootAlias(State, ArgMR);
      if (!Root)
        Root = ArgMR->getBaseRegion();
      if (Root) {
        // Transition to MaybeFreed regardless of previous state to reflect
        // that the helper might have released the resource.
        State = State->set<ResourceStateMap>(Root, RS_MaybeFreed);
        C.addTransition(State);
      }
    }
    return;
  }

  // Model direct free: arg0 -> Freed
  if (isFreeCall(Call, C)) {
    const MemRegion *ArgMR = getArgBaseRegion(Call, 0, C);
    if (ArgMR) {
      const MemRegion *Root = getRootAlias(State, ArgMR);
      if (!Root)
        Root = ArgMR->getBaseRegion();
      if (Root) {
        State = State->set<ResourceStateMap>(Root, RS_Freed);
        C.addTransition(State);
      }
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *Dst = Loc.getAsRegion();
  if (!Dst) {
    C.addTransition(State);
    return;
  }
  Dst = Dst->getBaseRegion();
  if (!Dst) {
    C.addTransition(State);
    return;
  }

  if (const MemRegion *Src = Val.getAsRegion()) {
    Src = Src->getBaseRegion();
    if (Src) {
      State = setAlias(State, Dst, Src);
      C.addTransition(State);
      return;
    }
  }

  // No aliasing to record for other kinds of values.
  C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->remove<ResourceStateMap>();
  State = State->remove<PtrAliasMap>();
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when a helper may free and then a shared cleanup frees again",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 114 |     const MemRegion *Next = State->get<PtrAliasMap>(Cur);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
