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
#include "llvm/ADT/SmallPtrSet.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track per-CPU pointer kind for regions.
// 0 = Unknown, 1 = LocalThisCPU (this_cpu_ptr), 2 = RemotePerCPU (per_cpu_ptr with explicit cpu arg not smp_processor_id()).
REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrKindMap, const MemRegion*, unsigned)

namespace {

enum PerCpuKind : unsigned {
  PCK_None   = 0,
  PCK_Local  = 1,
  PCK_Remote = 2
};

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker< check::Bind, check::Location > {
   // Unused default BT to satisfy template.
   mutable std::unique_ptr<BugType> BT;

   // Specific bug types we actually report.
   mutable std::unique_ptr<BugType> BTRemoteWrite;
   mutable std::unique_ptr<BugType> BTRMW;

   // Cache of fields that were observed accessed via a remote per_cpu_ptr.
   mutable llvm::SmallPtrSet<const FieldDecl*, 32> RemotePerCpuFields;

   public:
      SAGenTestChecker()
        : BT(new BugType(this, "Kernel Concurrency", "Per-CPU cross-CPU unsynchronized access")),
          BTRemoteWrite(new BugType(this, "Cross-CPU per-CPU write without WRITE_ONCE", "Concurrency")),
          BTRMW(new BugType(this, "RMW on per-CPU field without READ/WRITE_ONCE", "Concurrency")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helper: does this expression look like a call with name?
      bool isCallNamed(const CallExpr *CE, StringRef Name, CheckerContext &C) const {
        if (!CE) return false;
        const Expr *E = dyn_cast<Expr>(CE);
        if (!E) return false;
        return ExprHasName(E, Name, C);
      }

      bool isSmpProcessorIdExpr(const Expr *E, CheckerContext &C) const {
        if (!E) return false;
        return ExprHasName(E, "smp_processor_id", C);
      }

      // Classify per-cpu pointer kind from a call expression.
      unsigned classifyPerCpuFromCall(const CallExpr *CE, CheckerContext &C) const {
        if (!CE) return PCK_None;
        if (isCallNamed(CE, "this_cpu_ptr", C))
          return PCK_Local;

        if (isCallNamed(CE, "per_cpu_ptr", C)) {
          if (CE->getNumArgs() >= 2) {
            const Expr *CPUArg = CE->getArg(1);
            if (isSmpProcessorIdExpr(CPUArg, C))
              return PCK_Local;
            return PCK_Remote;
          }
          // If no cpu arg visible, conservatively treat as remote (cross-CPU) usage.
          return PCK_Remote;
        }
        return PCK_None;
      }

      // Attempt to determine kind for the base expression of a MemberExpr.
      unsigned getPerCpuKindFromBaseExpr(const Expr *Base, CheckerContext &C, ProgramStateRef State) const {
        if (!Base) return PCK_None;

        // First, try using program state mapping via the base's region.
        if (const MemRegion *MR = getMemRegionFromExpr(Base, C)) {
          MR = MR->getBaseRegion();
          if (MR) {
            if (const unsigned *K = State->get<PerCpuPtrKindMap>(MR))
              return *K;
          }
        }

        // Fallback: look inside the base for a call expression to classify.
        if (const CallExpr *InnerCall = findSpecificTypeInChildren<CallExpr>(Base)) {
          unsigned K = classifyPerCpuFromCall(InnerCall, C);
          if (K != PCK_None)
            return K;
        }

        return PCK_None;
      }

      void setPerCpuKindForRegion(ProgramStateRef &State, const MemRegion *MR, unsigned Kind) const {
        if (!MR) return;
        MR = MR->getBaseRegion();
        if (!MR) return;
        if (Kind == PCK_None) return;
        State = State->set<PerCpuPtrKindMap>(MR, Kind);
      }

      // Report helpers
      void reportRemoteWrite(const BinaryOperator *BO, const FieldDecl *FD, CheckerContext &C) const {
        if (!BTRemoteWrite) return;
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N) return;
        auto R = std::make_unique<PathSensitiveBugReport>(
          *BTRemoteWrite, "Cross-CPU write to per-CPU field without WRITE_ONCE", N);
        if (BO)
          R->addRange(BO->getSourceRange());
        if (FD)
          R->addNote("Field: " + FD->getNameAsString(), BO ? BO->getBeginLoc() : SourceLocation());
        C.emitReport(std::move(R));
      }

      void reportLocalRMW(const BinaryOperator *BO, const FieldDecl *FD, CheckerContext &C) const {
        if (!BTRMW) return;
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N) return;
        auto R = std::make_unique<PathSensitiveBugReport>(
          *BTRMW, "RMW of per-CPU field also accessed cross-CPU; use READ_ONCE/WRITE_ONCE", N);
        if (BO)
          R->addRange(BO->getSourceRange());
        if (FD)
          R->addNote("Field: " + FD->getNameAsString(), BO ? BO->getBeginLoc() : SourceLocation());
        C.emitReport(std::move(R));
      }
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track per-cpu pointer origin when binding to a variable/region.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (LHSReg) {
    LHSReg = LHSReg->getBaseRegion();

    // 1) If this bind is the result of a call expression (per_cpu_ptr/this_cpu_ptr), set kind for LHS.
    if (const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S)) {
      unsigned Kind = classifyPerCpuFromCall(CE, C);
      if (Kind != PCK_None) {
        setPerCpuKindForRegion(State, LHSReg, Kind);
      }
    }

    // 2) Alias propagation: if RHS is a region already known, propagate its kind to LHS.
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (RHSReg) {
        if (const unsigned *K = State->get<PerCpuPtrKindMap>(RHSReg)) {
          setPerCpuKindForRegion(State, LHSReg, *K);
        }
      }
    }

    // 3) Special-case: RHS is a MemberExpr whose base is tracked (e.g., statc = statc->parent;)
    if (const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(S, C)) {
      if (BO->isAssignmentOp()) {
        const Expr *R = BO->getRHS();
        if (R) R = R->IgnoreParenImpCasts();
        if (const auto *ME = dyn_cast_or_cast<MemberExpr>(R)) {
          unsigned K = getPerCpuKindFromBaseExpr(ME->getBase(), C, State);
          if (K != PCK_None) {
            setPerCpuKindForRegion(State, LHSReg, K);
          }
        }
      }
    }
  }

  // Detect writes/RMWs to per-CPU fields.
  if (const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(S, C)) {
    const Expr *L = BO->getLHS();
    if (L) L = L->IgnoreParenImpCasts();
    const auto *LME = dyn_cast_or_null<MemberExpr>(L);
    if (LME) {
      const FieldDecl *FD = dyn_cast<FieldDecl>(LME->getMemberDecl());
      if (FD) {
        unsigned Kind = getPerCpuKindFromBaseExpr(LME->getBase(), C, State);
        if (Kind == PCK_Remote) {
          // Mark field as remotely accessed.
          RemotePerCpuFields.insert(FD);

          // Remote write without WRITE_ONCE: check for simple assignment and (optionally) zeroing.
          if (BO->getOpcode() == BO_Assign) {
            if (!ExprHasName(BO, "WRITE_ONCE", C)) {
              bool IsZero = false;
              if (const Expr *RHS = BO->getRHS()) {
                llvm::APSInt EvalRes;
                if (EvaluateExprToInt(EvalRes, RHS, C))
                  IsZero = (EvalRes == 0);
              }
              // Warn on the common flush zeroing pattern; this catches the target bug.
              if (IsZero) {
                reportRemoteWrite(BO, FD, C);
              }
            }
          }
        } else if (Kind == PCK_Local) {
          // Local compound RMW. If the same field is accessed remotely, require READ_ONCE/WRITE_ONCE.
          if (BO->isCompoundAssignmentOp()) {
            if (RemotePerCpuFields.count(FD)) {
              if (!ExprHasName(BO, "READ_ONCE", C) && !ExprHasName(BO, "WRITE_ONCE", C)) {
                reportLocalRMW(BO, FD, C);
              }
            }
          }
        }
      }
    }
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad)
    return;

  // Heuristic: if we're loading from a member expression via a remote per_cpu_ptr base,
  // record that field as remotely accessed. This helps later local RMW checks.
  const MemberExpr *ME = findSpecificTypeInParents<MemberExpr>(S, C);
  if (!ME) return;

  ProgramStateRef State = C.getState();
  unsigned Kind = getPerCpuKindFromBaseExpr(ME->getBase(), C, State);
  if (Kind == PCK_Remote) {
    if (const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      RemotePerCpuFields.insert(FD);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect unsynchronized cross-CPU accesses to per-CPU fields (missing READ_ONCE/WRITE_ONCE)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 131 |           R->addNote("Field: " + FD->getNameAsString(), BO ? BO->getBeginLoc() : SourceLocation());

	- Error Messages: cannot convert ‘clang::SourceLocation’ to ‘const clang::ento::PathDiagnosticLocation&’

- Error Line: 144 |           R->addNote("Field: " + FD->getNameAsString(), BO ? BO->getBeginLoc() : SourceLocation());

	- Error Messages: cannot convert ‘clang::SourceLocation’ to ‘const clang::ento::PathDiagnosticLocation&’

- Error Line: 180 |         if (const auto *ME = dyn_cast_or_cast<MemberExpr>(R)) {

	- Error Messages: ‘dyn_cast_or_cast’ was not declared in this scope

- Error Line: 180 |         if (const auto *ME = dyn_cast_or_cast<MemberExpr>(R)) {

	- Error Messages: xpected primary-expression before ‘>’ token



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
