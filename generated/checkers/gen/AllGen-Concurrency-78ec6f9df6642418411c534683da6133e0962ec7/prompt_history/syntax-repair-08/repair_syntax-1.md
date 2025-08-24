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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps:
// PerCpuPtrMap: tracks pointer variables that point to per-CPU storage,
// with flags:
//   bit 0 (1): tracked
//   bit 1 (2): isRemote (true if from per_cpu_ptr(..., cpu) where cpu != smp_processor_id())
REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, unsigned)
// Track pointer aliasing relationships
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<CompoundAssignOperator>,
        check::PreStmt<UnaryOperator>,
        check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsynchronized per-CPU access", "Concurrency")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const;
      void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      const MemRegion *getBaseRegionForExpr(const Expr *E, CheckerContext &C) const;
      const MemRegion *resolveAlias(ProgramStateRef State, const MemRegion *MR) const;
      Optional<unsigned> getPerCpuFlags(ProgramStateRef State, const MemRegion *MR) const;
      bool isTracked(ProgramStateRef State, const MemRegion *MR) const;
      bool isRemote(ProgramStateRef State, const MemRegion *MR) const;

      bool isPerCpuCall(const CallExpr *CE, CheckerContext &C, bool &OutIsThisCpu, bool &OutIsPerCpuPtr, bool &OutIsRemote) const;
      bool rhsContainsPerCpuCall(const Expr *RHS, CheckerContext &C, bool &OutIsRemote) const;

      void trackPerCpuPointer(ProgramStateRef &State, const MemRegion *LHSReg, bool IsRemote) const;
      void copyTrackFromRHS(ProgramStateRef &State, const MemRegion *LHSReg, const MemRegion *RHSReg) const;

      const MemberExpr *extractMemberFromLHS(const Expr *E) const;
      const DeclRefExpr *extractBaseDeclRef(const MemberExpr *ME) const;

      bool isWrappedBy(CheckerContext &C, const Stmt *S, StringRef WrapperName) const;

      void report(CheckerContext &C, const Stmt *S, StringRef Msg) const;
};

// Get base region of an expression's memory region.
const MemRegion *SAGenTestChecker::getBaseRegionForExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

// Resolve simple alias chains.
const MemRegion *SAGenTestChecker::resolveAlias(ProgramStateRef State, const MemRegion *MR) const {
  if (!MR) return nullptr;
  const MemRegion *Cur = MR->getBaseRegion();
  int Steps = 0;
  while (Cur && Steps < 8) {
    const MemRegion *Next = State->get<PtrAliasMap>(Cur);
    if (!Next || Next == Cur)
      break;
    Cur = Next->getBaseRegion();
    Steps++;
  }
  return Cur;
}

Optional<unsigned> SAGenTestChecker::getPerCpuFlags(ProgramStateRef State, const MemRegion *MR) const {
  if (!MR) return llvm::None;
  MR = resolveAlias(State, MR);
  const unsigned *Flags = State->get<PerCpuPtrMap>(MR);
  if (!Flags) return llvm::None;
  return *Flags;
}

bool SAGenTestChecker::isTracked(ProgramStateRef State, const MemRegion *MR) const {
  auto F = getPerCpuFlags(State, MR);
  return F.hasValue() && ((*F & 1u) != 0);
}

bool SAGenTestChecker::isRemote(ProgramStateRef State, const MemRegion *MR) const {
  auto F = getPerCpuFlags(State, MR);
  return F.hasValue() && ((*F & 2u) != 0);
}

// Determine if CE is per_cpu_ptr or this_cpu_ptr and classify remote-ness.
// Returns true if it is one of those. Sets OutIsRemote accordingly.
bool SAGenTestChecker::isPerCpuCall(const CallExpr *CE, CheckerContext &C,
                                    bool &OutIsThisCpu,
                                    bool &OutIsPerCpuPtr,
                                    bool &OutIsRemote) const {
  OutIsThisCpu = false;
  OutIsPerCpuPtr = false;
  OutIsRemote = false;
  if (!CE) return false;

  bool IsPerCpu = false;
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    StringRef Name = FD->getName();
    if (Name == "this_cpu_ptr") {
      IsPerCpu = true;
      OutIsThisCpu = true;
    } else if (Name == "per_cpu_ptr") {
      IsPerCpu = true;
      OutIsPerCpuPtr = true;
    }
  } else {
    // Fallback to textual match
    const Expr *E = CE;
    if (ExprHasName(E, "this_cpu_ptr", C)) {
      IsPerCpu = true;
      OutIsThisCpu = true;
    } else if (ExprHasName(E, "per_cpu_ptr", C)) {
      IsPerCpu = true;
      OutIsPerCpuPtr = true;
    }
  }

  if (!IsPerCpu)
    return false;

  if (OutIsThisCpu) {
    OutIsRemote = false;
    return true;
  }

  if (OutIsPerCpuPtr) {
    // per_cpu_ptr(base, cpu_expr)
    if (CE->getNumArgs() >= 2) {
      const Expr *CpuE = CE->getArg(1);
      // Consider local if cpu_expr contains smp_processor_id, else remote
      if (ExprHasName(CpuE, "smp_processor_id", C))
        OutIsRemote = false;
      else
        OutIsRemote = true;
    } else {
      // Conservative: treat as remote if no arg found
      OutIsRemote = true;
    }
    return true;
  }

  return false;
}

// Find if RHS contains a call to per_cpu_ptr/this_cpu_ptr and return remote-ness.
bool SAGenTestChecker::rhsContainsPerCpuCall(const Expr *RHS, CheckerContext &C, bool &OutIsRemote) const {
  OutIsRemote = false;
  if (!RHS) return false;
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(RHS);
  if (!CE) return false;
  bool IsThis = false, IsPerCpuPtr = false, IsRemote = false;
  if (!isPerCpuCall(CE, C, IsThis, IsPerCpuPtr, IsRemote))
    return false;
  OutIsRemote = IsRemote;
  return true;
}

void SAGenTestChecker::trackPerCpuPointer(ProgramStateRef &State, const MemRegion *LHSReg, bool IsRemote) const {
  if (!LHSReg) return;
  LHSReg = LHSReg->getBaseRegion();
  unsigned Flags = 1u | (IsRemote ? 2u : 0u);
  State = State->set<PerCpuPtrMap>(LHSReg, Flags);
}

void SAGenTestChecker::copyTrackFromRHS(ProgramStateRef &State, const MemRegion *LHSReg, const MemRegion *RHSReg) const {
  if (!LHSReg || !RHSReg) return;
  LHSReg = LHSReg->getBaseRegion();
  RHSReg = RHSReg->getBaseRegion();
  const unsigned *Flags = State->get<PerCpuPtrMap>(RHSReg);
  if (!Flags) return;
  State = State->set<PerCpuPtrMap>(LHSReg, *Flags);
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
}

const MemberExpr *SAGenTestChecker::extractMemberFromLHS(const Expr *E) const {
  if (!E) return nullptr;
  // If E itself is a MemberExpr
  if (const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenImpCasts()))
    return ME;
  // Otherwise search children for a MemberExpr
  return findSpecificTypeInChildren<MemberExpr>(E);
}

const DeclRefExpr *SAGenTestChecker::extractBaseDeclRef(const MemberExpr *ME) const {
  if (!ME) return nullptr;
  const Expr *Base = ME->getBase();
  if (!Base) return nullptr;
  Base = Base->IgnoreParenImpCasts();
  return dyn_cast<DeclRefExpr>(Base);
}

// Check whether S (or its expression text) contains the wrapper macro name.
bool SAGenTestChecker::isWrappedBy(CheckerContext &C, const Stmt *S, StringRef WrapperName) const {
  if (!S) return false;
  const Expr *E = dyn_cast<Expr>(S);
  if (!E) return false;
  if (ExprHasName(E, WrapperName, C))
    return true;
  // Try to look a bit upwards (best-effort)
  const Expr *ParentE = findSpecificTypeInParents<Expr>(E, C);
  if (ParentE && ExprHasName(ParentE, WrapperName, C))
    return true;
  return false;
}

void SAGenTestChecker::report(CheckerContext &C, const Stmt *S, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// Track declarations with initializers from per_cpu_ptr/this_cpu_ptr
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD || !VD->hasInit())
      continue;
    if (!VD->getType()->isPointerType())
      continue;

    const Expr *Init = VD->getInit();
    if (!Init) continue;

    // If initializer contains per_cpu_ptr/this_cpu_ptr
    bool IsRemote = false;
    if (!rhsContainsPerCpuCall(Init, C, IsRemote))
      continue;

    // Get region of declared variable
    SVal LV = C.getSValBuilder().getLValue(VD, LCtx);
    const MemRegion *LHSReg = LV.getAsRegion();
    if (!LHSReg) continue;
    LHSReg = LHSReg->getBaseRegion();

    trackPerCpuPointer(State, LHSReg, IsRemote);
  }

  if (State != C.getState())
    C.addTransition(State);
}

// Track assignments and aliasing, detect per-CPU pointer flow
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();

  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;

  // 1) RHS contains per_cpu_ptr/this_cpu_ptr
  bool IsRemote = false;
  if (rhsContainsPerCpuCall(RHS, C, IsRemote)) {
    trackPerCpuPointer(State, LHSReg, IsRemote);
    C.addTransition(State);
    return;
  }

  // 2) RHS is alias of a tracked per-CPU pointer
  const MemRegion *RHSReg = getBaseRegionForExpr(RHS, C);
  if (RHSReg) {
    RHSReg = resolveAlias(State, RHSReg);
    if (isTracked(State, RHSReg)) {
      copyTrackFromRHS(State, LHSReg, RHSReg);
      C.addTransition(State);
      return;
    }
  }

  // 3) Otherwise, remove tracking on LHS to avoid stale data
  if (State->contains<PerCpuPtrMap>(LHSReg)) {
    State = State->remove<PerCpuPtrMap>(LHSReg);
    C.addTransition(State);
  }
}

// Detect compound assignments (e.g., +=) to per-CPU fields
void SAGenTestChecker::checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const {
  const Expr *LHS = CAO->getLHS();
  if (!LHS) return;

  const MemberExpr *ME = extractMemberFromLHS(LHS);
  if (!ME) return;

  const DeclRefExpr *BaseDRE = extractBaseDeclRef(ME);
  if (!BaseDRE) return;

  const MemRegion *BaseReg = getBaseRegionForExpr(BaseDRE, C);
  if (!BaseReg) return;

  ProgramStateRef State = C.getState();
  if (!isTracked(State, BaseReg))
    return;

  // Report: RMW on per-CPU field without READ_ONCE/WRITE_ONCE
  report(C, CAO, "Per-CPU field updated with compound assignment without READ_ONCE/WRITE_ONCE.");
}

// Detect ++/-- on per-CPU fields
void SAGenTestChecker::checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const {
  UnaryOperatorKind Op = UO->getOpcode();
  if (Op != UO_PostInc && Op != UO_PreInc && Op != UO_PostDec && Op != UO_PreDec)
    return;

  const Expr *Sub = UO->getSubExpr();
  if (!Sub) return;

  const MemberExpr *ME = extractMemberFromLHS(Sub);
  if (!ME) return;

  const DeclRefExpr *BaseDRE = extractBaseDeclRef(ME);
  if (!BaseDRE) return;

  const MemRegion *BaseReg = getBaseRegionForExpr(BaseDRE, C);
  if (!BaseReg) return;

  ProgramStateRef State = C.getState();
  if (!isTracked(State, BaseReg))
    return;

  report(C, UO, "Per-CPU field increment/decrement without READ_ONCE/WRITE_ONCE.");
}

// Enforce READ_ONCE/WRITE_ONCE around cross-CPU per-CPU member accesses and plain writes
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  const Expr *E = dyn_cast_or_null<Expr>(S);
  if (!E) return;

  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(E);
  if (!ME) return;

  const DeclRefExpr *BaseDRE = extractBaseDeclRef(ME);
  if (!BaseDRE) return;

  const MemRegion *BaseReg = getBaseRegionForExpr(BaseDRE, C);
  if (!BaseReg) return;

  ProgramStateRef State = C.getState();
  if (!isTracked(State, BaseReg))
    return;

  bool WrappedRead = isWrappedBy(C, S, "READ_ONCE");
  bool WrappedWrite = isWrappedBy(C, S, "WRITE_ONCE");
  bool Remote = isRemote(State, BaseReg);

  if (IsLoad) {
    if (Remote && !WrappedRead) {
      report(C, S, "Remote per-CPU read without READ_ONCE.");
    }
  } else {
    // Store
    if (Remote && !WrappedWrite) {
      report(C, S, "Remote per-CPU write without WRITE_ONCE.");
    } else if (!WrappedWrite) {
      // Also warn for plain writes to per-CPU fields; may race with cross-CPU access.
      report(C, S, "Per-CPU field write without WRITE_ONCE; may race with cross-CPU access.");
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsynchronized per-CPU accesses (missing READ_ONCE/WRITE_ONCE) including RMW on per-CPU fields",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 57 |       Optional<unsigned> getPerCpuFlags(ProgramStateRef State, const MemRegion *MR) const;

	- Error Messages: ‘Optional’ does not name a type

- Error Line: 89 |     const MemRegion *Next = State->get<PtrAliasMap>(Cur);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization

- Error Line: 98 | Optional<unsigned> SAGenTestChecker::getPerCpuFlags(ProgramStateRef State, const MemRegion *MR) const {

	- Error Messages: ‘Optional’ does not name a type

- Error Line: 107 |   auto F = getPerCpuFlags(State, MR);

	- Error Messages: ‘getPerCpuFlags’ was not declared in this scope

- Error Line: 112 |   auto F = getPerCpuFlags(State, MR);

	- Error Messages: ‘getPerCpuFlags’ was not declared in this scope

- Error Line: 268 |     SVal LV = C.getSValBuilder().getLValue(VD, LCtx);

	- Error Messages: ‘class clang::ento::SValBuilder’ has no member named ‘getLValue’; did you mean ‘getMinValue’?



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
