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
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(PerCpuPtrSet, const MemRegion*) // Track per-CPU pointer regions

namespace {
class SAGenTestChecker : public Checker<check::Bind, check::PostCall> {
   // A generic BT (not used directly) plus two specific bug types.
   mutable std::unique_ptr<BugType> BT;
   mutable std::unique_ptr<BugType> BT_RMW;
   mutable std::unique_ptr<BugType> BT_Plain;

   public:
      SAGenTestChecker()
        : BT(new BugType(this, "Concurrency", "Per-CPU data-race (missing READ/WRITE_ONCE)")),
          BT_RMW(new BugType(this, "Per-CPU RMW without READ_ONCE/WRITE_ONCE", "Concurrency")),
          BT_Plain(new BugType(this, "Per-CPU plain store without WRITE_ONCE", "Concurrency")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static bool isPerCpuGetterName(StringRef N);
      static bool sameExpr(const Expr *A, const Expr *B);
      bool isPerCpuGetterCall(const CallExpr *CE, CheckerContext &C) const;
      bool baseIsPerCpuPtr(const Expr *BaseRaw, CheckerContext &C) const;
      bool isZero(const Expr *E, CheckerContext &C) const;
      bool isWriteOnceContext(const Expr *E, const Stmt *S, CheckerContext &C) const;

      void propagatePerCpuAlias(const MemRegion *LHSBaseReg, const Expr *RHS, CheckerContext &C, ProgramStateRef &State) const;

      void maybeReportRMWOnPerCpuField(const Stmt *S, CheckerContext &C) const;
      void maybeReportPlainZeroStoreOnPerCpuField(const Stmt *S, CheckerContext &C) const;

      void reportRMW(const MemberExpr *ME, CheckerContext &C) const;
      void reportPlainStore(const MemberExpr *ME, CheckerContext &C) const;
};

// ---- Helper implementations ----

bool SAGenTestChecker::isPerCpuGetterName(StringRef N) {
  return N == "this_cpu_ptr" ||
         N == "per_cpu_ptr" ||
         N == "raw_cpu_ptr" ||
         N == "per_cpu_ptr_no_check" ||
         N == "get_cpu_ptr";
}

bool SAGenTestChecker::sameExpr(const Expr *A, const Expr *B) {
  if (!A || !B) return false;
  return A->IgnoreParenImpCasts() == B->IgnoreParenImpCasts();
}

bool SAGenTestChecker::isPerCpuGetterCall(const CallExpr *CE, CheckerContext &C) const {
  if (!CE) return false;
  // Use textual matching for robustness with macros/wrappers.
  return ExprHasName(CE, "this_cpu_ptr", C) ||
         ExprHasName(CE, "per_cpu_ptr", C) ||
         ExprHasName(CE, "raw_cpu_ptr", C) ||
         ExprHasName(CE, "per_cpu_ptr_no_check", C) ||
         ExprHasName(CE, "get_cpu_ptr", C);
}

bool SAGenTestChecker::baseIsPerCpuPtr(const Expr *BaseRaw, CheckerContext &C) const {
  if (!BaseRaw) return false;

  // If the base is a per-cpu getter call, it's per-cpu for sure.
  if (const auto *CE = dyn_cast<CallExpr>(BaseRaw)) {
    if (isPerCpuGetterCall(CE, C))
      return true;
  }

  // Otherwise, check whether the region is recorded as per-cpu.
  const MemRegion *MR = getMemRegionFromExpr(BaseRaw, C);
  if (!MR) return false;
  MR = MR->getBaseRegion();
  if (!MR) return false;

  ProgramStateRef State = C.getState();
  return State->contains<PerCpuPtrSet>(MR);
}

bool SAGenTestChecker::isZero(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C))
    return Res == 0;
  return false;
}

// Determine if the write is explicitly wrapped by WRITE_ONCE.
// We check parent CallExpr for "WRITE_ONCE", and as a fallback, we also
// check the entire statement source text (BinaryOperator/Expr) for "WRITE_ONCE".
bool SAGenTestChecker::isWriteOnceContext(const Expr *E, const Stmt *S, CheckerContext &C) const {
  if (!E) return false;

  if (const CallExpr *ParentCall = findSpecificTypeInParents<CallExpr>(E, C)) {
    if (ExprHasName(ParentCall, "WRITE_ONCE", C))
      return true;
  }

  if (const Expr *SE = dyn_cast_or_null<Expr>(S)) {
    if (ExprHasName(SE, "WRITE_ONCE", C))
      return true;
  }
  return false;
}

void SAGenTestChecker::propagatePerCpuAlias(const MemRegion *LHSBaseReg, const Expr *RHS, CheckerContext &C, ProgramStateRef &State) const {
  if (!LHSBaseReg || !RHS) return;

  // Case 1: RHS is a direct per-cpu getter call.
  if (const auto *CE = dyn_cast<CallExpr>(RHS->IgnoreParenImpCasts())) {
    if (isPerCpuGetterCall(CE, C)) {
      State = State->add<PerCpuPtrSet>(LHSBaseReg);
      return;
    }
  }

  // Case 2: RHS is a reference to another pointer already known as per-cpu.
  if (const MemRegion *RHSReg = getMemRegionFromExpr(RHS, C)) {
    RHSReg = RHSReg->getBaseRegion();
    if (RHSReg && State->contains<PerCpuPtrSet>(RHSReg)) {
      State = State->add<PerCpuPtrSet>(LHSBaseReg);
      return;
    }
  }

  // Case 3: RHS is a member derived from a per-cpu pointer (e.g., statc->parent).
  if (const auto *ME = dyn_cast<MemberExpr>(RHS->IgnoreParenImpCasts())) {
    const Expr *BaseRaw = ME->getBase(); // do not IgnoreImplicit() here for region extraction rules
    if (baseIsPerCpuPtr(BaseRaw, C)) {
      // Only propagate if RHS type is a pointer (alias propagation of pointer value).
      if (RHS->getType()->isPointerType())
        State = State->add<PerCpuPtrSet>(LHSBaseReg);
      return;
    }
  }
}

// Inspect the statement for compound assignment or inc/dec on a per-cpu field.
void SAGenTestChecker::maybeReportRMWOnPerCpuField(const Stmt *S, CheckerContext &C) const {
  if (!S) return;

  // Find a MemberExpr within S
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(S);
  if (!ME) return;

  // Check for compound assignment like (field += x) where ME is the LHS
  if (const auto *CAO = findSpecificTypeInParents<CompoundAssignOperator>(ME, C)) {
    if (sameExpr(CAO->getLHS(), ME)) {
      const Expr *BaseRaw = ME->getBase(); // raw for region extraction
      if (baseIsPerCpuPtr(BaseRaw, C)) {
        reportRMW(ME, C);
      }
      return;
    }
  }

  // Check for ++/-- on the field
  if (const auto *UO = findSpecificTypeInParents<UnaryOperator>(ME, C)) {
    if ((UO->getOpcode() == UO_PreInc || UO->getOpcode() == UO_PreDec ||
         UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PostDec) &&
        sameExpr(UO->getSubExpr(), ME)) {
      const Expr *BaseRaw = ME->getBase();
      if (baseIsPerCpuPtr(BaseRaw, C)) {
        reportRMW(ME, C);
      }
      return;
    }
  }
}

// Inspect for plain assignment "field = 0" without WRITE_ONCE.
void SAGenTestChecker::maybeReportPlainZeroStoreOnPerCpuField(const Stmt *S, CheckerContext &C) const {
  if (!S) return;
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(S);
  if (!ME) return;

  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(ME, C)) {
    if (BO->isAssignmentOp() && !BO->isCompoundAssignmentOp()) {
      if (sameExpr(BO->getLHS(), ME)) {
        const Expr *RHS = BO->getRHS();
        if (RHS && isZero(RHS->IgnoreParenImpCasts(), C)) {
          // Check if it's in a WRITE_ONCE context; if yes, do not warn.
          if (isWriteOnceContext(ME, S, C))
            return;

          const Expr *BaseRaw = ME->getBase();
          if (baseIsPerCpuPtr(BaseRaw, C)) {
            reportPlainStore(ME, C);
          }
        }
      }
    }
  }
}

void SAGenTestChecker::reportRMW(const MemberExpr *ME, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT_RMW, "RMW on per-CPU field without READ_ONCE/WRITE_ONCE", N);
  if (ME)
    R->addRange(ME->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportPlainStore(const MemberExpr *ME, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT_Plain, "Plain store to per-CPU field; use WRITE_ONCE", N);
  if (ME)
    R->addRange(ME->getSourceRange());
  C.emitReport(std::move(R));
}

// ---- Callbacks ----

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // 1) Propagate per-CPU pointer aliases.
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (LHSReg)
    LHSReg = LHSReg->getBaseRegion();

  // If RHS is already a known per-cpu pointer region, add LHS as per-cpu.
  if (LHSReg) {
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (RHSReg && State->contains<PerCpuPtrSet>(RHSReg)) {
        State = State->add<PerCpuPtrSet>(LHSReg);
      }
    } else {
      // Try AST-based deduction: only if S is DeclStmt or BinaryOperator assignment.
      const Expr *RHSExpr = nullptr;

      if (const auto *DS = dyn_cast_or_null<DeclStmt>(S)) {
        for (const Decl *D : DS->decls()) {
          if (const auto *VD = dyn_cast<VarDecl>(D)) {
            if (const Expr *Init = VD->getInit()) {
              RHSExpr = Init;
              // LHSReg already computed from Loc; we also ensure pointer type if possible.
              // If it is a pointer, propagate based on RHS pattern.
              if (VD->getType()->isPointerType())
                propagatePerCpuAlias(LHSReg, RHSExpr, C, State);
            }
          }
        }
      } else if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
        if (BO->isAssignmentOp()) {
          RHSExpr = BO->getRHS();
          // LHSExpr pointer-type check (best effort).
          const Expr *LHSExpr = BO->getLHS();
          if (LHSExpr && LHSExpr->getType()->isPointerType())
            propagatePerCpuAlias(LHSReg, RHSExpr, C, State);
        }
      }
    }
  }

  // 2) Detect suspicious RMW on per-CPU fields.
  maybeReportRMWOnPerCpuField(S, C);

  // 3) Detect suspicious plain reset to zero on per-CPU fields.
  maybeReportPlainZeroStoreOnPerCpuField(S, C);

  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) {
    C.addTransition(State);
    return;
  }

  // Opportunistically tag return value of per-cpu getters.
  if (const auto *CE = dyn_cast<CallExpr>(Origin)) {
    if (isPerCpuGetterCall(CE, C)) {
      if (const MemRegion *MR = Call.getReturnValue().getAsRegion()) {
        MR = MR->getBaseRegion();
        if (MR)
          State = State->add<PerCpuPtrSet>(MR);
      }
    }
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects plain RMW/reset on per-CPU fields without READ_ONCE/WRITE_ONCE",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
