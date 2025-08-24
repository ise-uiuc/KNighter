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

using namespace clang;
using namespace ento;
using namespace taint;

// Track the "checked" state of pointers that originate from devm_* allocators.
// Keyed by the pointee MemRegion (the region returned by devm_*), value:
//   0 = Unchecked (may be NULL)
//   1 = Checked   (has been NULL-checked on this path)
REGISTER_MAP_WITH_PROGRAMSTATE(DevmPtrState, const MemRegion*, unsigned)

// Optional alias map placeholder (not strictly needed when we key by pointee),
// but kept for extensibility and to follow the suggested pattern.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::BranchCondition,
        check::Location,
        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unchecked devm allocation dereference", "Null pointer dereference")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isKnownDevmAllocatorName(StringRef Name);
      static bool isDevmAllocatorExpr(const Expr *E, CheckerContext &C);
      static const MemRegion *getPtrRegionFromExpr(const Expr *E, CheckerContext &C);
      static ProgramStateRef setChecked(ProgramStateRef State, const MemRegion *R);
      static ProgramStateRef setUnchecked(ProgramStateRef State, const MemRegion *R);
      void reportDerefUnchecked(const Stmt *S, const Expr *BaseE, CheckerContext &C) const;
      void reportPassToDerefUnchecked(const CallEvent &Call, unsigned ArgIdx, CheckerContext &C) const;

      template <typename T>
      const T* findInParents(const Stmt *S, CheckerContext &C) const {
        return findSpecificTypeInParents<T>(S, C);
      }
};

// Determine if the given function name is a devm_* allocator we want to track.
bool SAGenTestChecker::isKnownDevmAllocatorName(StringRef Name) {
  return Name.equals("devm_kzalloc") ||
         Name.equals("devm_kmalloc") ||
         Name.equals("devm_kcalloc") ||
         Name.equals("devm_kmalloc_array") ||
         Name.equals("devm_kstrdup");
}

// Check if an expression is a call to a known devm_* allocator.
bool SAGenTestChecker::isDevmAllocatorExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  // Try each known devm allocator via source text matching.
  return ExprHasName(E, "devm_kzalloc", C) ||
         ExprHasName(E, "devm_kmalloc", C) ||
         ExprHasName(E, "devm_kcalloc", C) ||
         ExprHasName(E, "devm_kmalloc_array", C) ||
         ExprHasName(E, "devm_kstrdup", C);
}

// Get the pointee MemRegion from an expression representing a pointer value.
const MemRegion *SAGenTestChecker::getPtrRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

ProgramStateRef SAGenTestChecker::setChecked(ProgramStateRef State, const MemRegion *R) {
  if (!R) return State;
  const unsigned *Cur = State->get<DevmPtrState>(R);
  if (Cur && *Cur == 0)
    State = State->set<DevmPtrState>(R, 1);
  return State;
}

ProgramStateRef SAGenTestChecker::setUnchecked(ProgramStateRef State, const MemRegion *R) {
  if (!R) return State;
  State = State->set<DevmPtrState>(R, 0);
  return State;
}

void SAGenTestChecker::reportDerefUnchecked(const Stmt *S, const Expr *BaseE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked devm allocation may be NULL and is dereferenced", N);
  if (S)
    R->addRange(S->getSourceRange());
  if (BaseE)
    R->addRange(BaseE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportPassToDerefUnchecked(const CallEvent &Call, unsigned ArgIdx, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked devm allocation may be NULL and is passed to a function that dereferences it", N);
  if (const Expr *OE = Call.getOriginExpr())
    R->addRange(OE->getSourceRange());
  if (ArgIdx < Call.getNumArgs())
    if (const Expr *AE = Call.getArgExpr(ArgIdx))
      R->addRange(AE->getSourceRange());
  C.emitReport(std::move(R));
}

// After a call: if it is a devm_* allocator, mark the returned region as Unchecked.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return;

  // Only track known devm_* allocators.
  bool IsDevmAlloc = false;
  // Prefer ExprHasName for robust matching.
  for (const char *Name : {"devm_kzalloc", "devm_kmalloc", "devm_kcalloc", "devm_kmalloc_array", "devm_kstrdup"}) {
    if (ExprHasName(OE, Name, C)) {
      IsDevmAlloc = true;
      break;
    }
  }
  if (!IsDevmAlloc) return;

  ProgramStateRef State = C.getState();
  const MemRegion *RetR = Call.getReturnValue().getAsRegion();
  if (!RetR) return;
  RetR = RetR->getBaseRegion();
  if (!RetR) return;

  State = setUnchecked(State, RetR);
  C.addTransition(State);
}

// Before a call: if a known-dereference function is called with an unchecked devm pointer, report.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    const MemRegion *MR = getPtrRegionFromExpr(ArgE, C);
    if (!MR)
      continue;

    const unsigned *St = State->get<DevmPtrState>(MR);
    if (St && *St == 0) {
      reportPassToDerefUnchecked(Call, Idx, C);
      // Do not early return; report for all problematic args.
    }
  }
}

// Observe branch conditions to mark devm pointers as "Checked" once they appear in NULL tests.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;
  ProgramStateRef State = C.getState();

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  CondE = CondE->IgnoreParenCasts();

  auto MarkPtrExprChecked = [&](const Expr *PtrE) {
    const MemRegion *MR = getPtrRegionFromExpr(PtrE, C);
    if (!MR) return;
    const unsigned *St = State->get<DevmPtrState>(MR);
    if (St) {
      State = setChecked(State, MR);
    }
  };

  // if (!p)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      MarkPtrExprChecked(UO->getSubExpr()->IgnoreParenCasts());
    }
  }
  // if (p == NULL) or if (p != NULL)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      const Expr *PtrE = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrE = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrE = LHS;

      if (PtrE)
        MarkPtrExprChecked(PtrE);
    }
  }
  // if (p)
  else {
    // If condition is a raw pointer expression.
    if (CondE->getType()->isPointerType())
      MarkPtrExprChecked(CondE);
  }

  C.addTransition(State);
}

// Detect dereferences of unchecked devm pointers via ->, *ptr, or ptr[index].
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *BaseE = nullptr;
  const MemRegion *BaseMR = nullptr;

  // 1) Look for MemberExpr with '->'
  if (const auto *ME = findInParents<MemberExpr>(S, C)) {
    if (ME->isArrow()) {
      BaseE = ME->getBase()->IgnoreParenCasts();
      BaseMR = getPtrRegionFromExpr(BaseE, C);
    }
  }

  // 2) If not found, check UnaryOperator '*'
  if (!BaseMR) {
    if (const auto *UO = findInParents<UnaryOperator>(S, C)) {
      if (UO->getOpcode() == UO_Deref) {
        BaseE = UO->getSubExpr()->IgnoreParenCasts();
        BaseMR = getPtrRegionFromExpr(BaseE, C);
      }
    }
  }

  // 3) ArraySubscriptExpr: ptr[i]
  if (!BaseMR) {
    if (const auto *ASE = findInParents<ArraySubscriptExpr>(S, C)) {
      BaseE = ASE->getBase()->IgnoreParenCasts();
      BaseMR = getPtrRegionFromExpr(BaseE, C);
    }
  }

  if (!BaseMR)
    return;

  const unsigned *St = State->get<DevmPtrState>(BaseMR);
  if (St && *St == 0) {
    // Unchecked devm allocation is being dereferenced.
    reportDerefUnchecked(S, BaseE, C);
  }
}

// Observe binds to optionally track devm allocation in direct assignments as well.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If RHS is a devm_* call, mark its return region as Unchecked.
  if (S) {
    if (const auto *CE = findSpecificTypeInChildren<CallExpr>(S)) {
      if (isDevmAllocatorExpr(CE, C)) {
        const MemRegion *MR = getPtrRegionFromExpr(CE, C);
        if (MR) {
          State = setUnchecked(State, MR);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // We do not need to explicitly propagate aliasing because the map is keyed
  // by the pointee region. Any alias to the same pointee uses the same key.
  // Still, if RHS is not a region (e.g., NULL literal or integer), nothing to track.
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of devm_* allocation without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
