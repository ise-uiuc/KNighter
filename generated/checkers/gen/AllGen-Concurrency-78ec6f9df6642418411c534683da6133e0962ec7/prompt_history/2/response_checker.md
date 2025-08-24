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
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: mark pointer regions that are known to point to per-CPU storage.
REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion *, bool)

namespace {
// The checker callbacks are to be decided.
class SAGenTestChecker : public Checker<check::Bind, check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Non-atomic per-CPU field access", "Concurrency")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helper functions
      static bool isPerCpuGetterName(StringRef N);
      static StringRef getCallName(const CallExpr *CE);
      static bool rhsContainsPerCpuGetter(const Stmt *S, CheckerContext &C);
      static bool isStatsUpdatesME(const MemberExpr *ME);
      static const MemRegion *getBaseRegionOfMember(const MemberExpr *ME, CheckerContext &C);
      static bool inOnceMacroContext(const Stmt *S, CheckerContext &C, bool IsStore);
      static bool isPerCpuBase(const Expr *Base, CheckerContext &C);
      void reportNonAtomicStore(const Stmt *S, const MemberExpr *ME, CheckerContext &C) const;
};

bool SAGenTestChecker::isPerCpuGetterName(StringRef N) {
  return N.equals("this_cpu_ptr") || N.equals("per_cpu_ptr");
}

StringRef SAGenTestChecker::getCallName(const CallExpr *CE) {
  if (!CE) return StringRef();
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (const IdentifierInfo *II = FD->getIdentifier())
      return II->getName();
  }
  return StringRef();
}

bool SAGenTestChecker::rhsContainsPerCpuGetter(const Stmt *S, CheckerContext &C) {
  if (!S) return false;
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE) return false;

  StringRef N = getCallName(CE);
  if (isPerCpuGetterName(N))
    return true;

  // Also check source text to cover macro/wrapper cases
  if (ExprHasName(CE, "this_cpu_ptr", C) || ExprHasName(CE, "per_cpu_ptr", C))
    return true;

  return false;
}

bool SAGenTestChecker::isStatsUpdatesME(const MemberExpr *ME) {
  if (!ME) return false;
  return ME->getMemberNameInfo().getAsString() == "stats_updates";
}

const MemRegion *SAGenTestChecker::getBaseRegionOfMember(const MemberExpr *ME, CheckerContext &C) {
  if (!ME) return nullptr;
  const Expr *BaseE = ME->getBase();
  if (!BaseE) return nullptr;
  BaseE = BaseE->IgnoreParenImpCasts();
  const MemRegion *R = getMemRegionFromExpr(BaseE, C);
  if (!R) return nullptr;
  return R->getBaseRegion();
}

bool SAGenTestChecker::inOnceMacroContext(const Stmt *S, CheckerContext &C, bool IsStore) {
  if (!S) return false;
  // Check if inside a call expression that contains READ_ONCE/WRITE_ONCE.
  const CallExpr *ParentCall = findSpecificTypeInParents<CallExpr>(S, C);
  if (ParentCall) {
    if (IsStore && ExprHasName(ParentCall, "WRITE_ONCE", C))
      return true;
    if (!IsStore && ExprHasName(ParentCall, "READ_ONCE", C))
      return true;
  }
  // Fallback: check the statement text itself (best effort).
  if (const Expr *E = dyn_cast<Expr>(S)) {
    if (IsStore && ExprHasName(E, "WRITE_ONCE", C))
      return true;
    if (!IsStore && ExprHasName(E, "READ_ONCE", C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isPerCpuBase(const Expr *Base, CheckerContext &C) {
  if (!Base) return false;
  const MemRegion *R = getMemRegionFromExpr(const_cast<Expr *>(Base), C);
  if (!R) return false;
  R = R->getBaseRegion();
  if (!R) return false;

  ProgramStateRef State = C.getState();
  const bool *Tag = State->get<PerCpuPtrMap>(R);
  return Tag && *Tag;
}

void SAGenTestChecker::reportNonAtomicStore(const Stmt *S, const MemberExpr *ME, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Non-atomic write to per-CPU 'stats_updates'; use WRITE_ONCE.", N);

  if (ME)
    R->addRange(ME->getSourceRange());
  else
    R->addRange(S->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *Dst = Loc.getAsRegion();
  if (!Dst) return;
  Dst = Dst->getBaseRegion();
  if (!Dst) return;

  // Ensure destination is a pointer-typed region.
  if (const auto *TVR = dyn_cast<TypedValueRegion>(Dst)) {
    QualType T = TVR->getValueType();
    if (!T.isNull() && T->isPointerType()) {
      bool Changed = false;

      // Case A: RHS explicitly calls per-CPU getters.
      if (rhsContainsPerCpuGetter(S, C)) {
        State = State->set<PerCpuPtrMap>(Dst, true);
        Changed = true;
      } else {
        // Case B: Propagate from another per-CPU pointer region on simple aliasing.
        if (const MemRegion *Src = Val.getAsRegion()) {
          Src = Src->getBaseRegion();
          if (Src) {
            if (const bool *Tag = State->get<PerCpuPtrMap>(Src)) {
              if (*Tag) {
                State = State->set<PerCpuPtrMap>(Dst, true);
                Changed = true;
              }
            } else {
              // Heuristic: if RHS is a member access whose base is per-CPU, propagate.
              // E.g., statc = statc->parent;
              if (S) {
                if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
                  const Expr *BaseE = ME->getBase();
                  if (BaseE && isPerCpuBase(BaseE->IgnoreParenImpCasts(), C)) {
                    State = State->set<PerCpuPtrMap>(Dst, true);
                    Changed = true;
                  }
                }
              }
            }
          }
        }
      }

      if (Changed)
        C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // We focus on non-atomic stores to per-CPU statc->stats_updates.
  if (IsLoad)
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R) return;

  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(S);
  if (!ME) return;
  if (!isStatsUpdatesME(ME))
    return;

  const Expr *BaseE = ME->getBase();
  if (!BaseE) return;
  BaseE = BaseE->IgnoreParenImpCasts();

  if (!isPerCpuBase(BaseE, C))
    return;

  if (inOnceMacroContext(S, C, /*IsStore=*/true))
    return;

  reportNonAtomicStore(S, ME, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect plain stores/updates to per-CPU stats_updates without WRITE_ONCE/READ_ONCE",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
