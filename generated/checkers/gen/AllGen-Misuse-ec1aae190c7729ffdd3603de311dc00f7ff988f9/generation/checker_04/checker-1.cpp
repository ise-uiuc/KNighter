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
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitObjMap, const MemRegion*, bool)

namespace {

// Compatibility helper for CountedByAttr API across Clang versions.
template <typename T>
static auto getCountedByExprCompatImpl(const T *A, int)
    -> decltype(A->getCountedBy(), static_cast<const Expr *>(nullptr)) {
  return A->getCountedBy();
}
template <typename T>
static auto getCountedByExprCompatImpl(const T *A, long)
    -> decltype(A->getCountedByExpr(), static_cast<const Expr *>(nullptr)) {
  return A->getCountedByExpr();
}
template <typename T>
static auto getCountedByExprCompatImpl(const T *A, double)
    -> decltype(A->getExpr(), static_cast<const Expr *>(nullptr)) {
  return A->getExpr();
}
static const Expr *getCountedByExprCompat(const CountedByAttr *A) {
  return getCountedByExprCompatImpl(A, 0);
}

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::Bind,
    check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Flex-array write before counter init (__counted_by)", "Memory Safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C);
      static bool isZeroingAllocator(const CallEvent &Call, CheckerContext &C);
      static bool isMemWriteCall(const CallEvent &Call, CheckerContext &C);

      static const FieldRegion* getFieldRegionFromExpr(const Expr *E, CheckerContext &C);
      static const FieldRegion* findFieldRegionInRegion(const MemRegion *R);

      static const MemRegion* getBaseOf(const MemRegion *R);

      static bool isFlexibleArrayWithCountedBy(const FieldDecl *FD);
      static bool recordHasCountedByFlexArray(const RecordDecl *RD);
      static bool isCounterFieldForAnyCountedBy(const FieldDecl *FD);

      void reportAt(const Stmt *S, CheckerContext &C) const;
      void reportAtExpr(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

bool SAGenTestChecker::isZeroingAllocator(const CallEvent &Call, CheckerContext &C) {
  return callHasName(Call, "kzalloc", C) ||
         callHasName(Call, "kcalloc", C) ||
         callHasName(Call, "kzalloc_array", C) ||
         callHasName(Call, "devm_kzalloc", C) ||
         callHasName(Call, "devm_kcalloc", C);
}

bool SAGenTestChecker::isMemWriteCall(const CallEvent &Call, CheckerContext &C) {
  // Destination is arg0 for all of these in the kernel (memcpy/memmove/memset/copy_from_user).
  return callHasName(Call, "memcpy", C) ||
         callHasName(Call, "memmove", C) ||
         callHasName(Call, "memset", C) ||
         callHasName(Call, "copy_from_user", C);
}

const MemRegion* SAGenTestChecker::getBaseOf(const MemRegion *R) {
  if (!R) return nullptr;
  return R->getBaseRegion();
}

const FieldRegion* SAGenTestChecker::findFieldRegionInRegion(const MemRegion *R) {
  const MemRegion *Cur = R;
  while (Cur) {
    if (const auto *FR = dyn_cast<FieldRegion>(Cur))
      return FR;
    if (const auto *ER = dyn_cast<ElementRegion>(Cur)) {
      Cur = ER->getSuperRegion();
      continue;
    }
    if (const auto *SR = dyn_cast<SubRegion>(Cur)) {
      Cur = SR->getSuperRegion();
      continue;
    }
    break;
  }
  return nullptr;
}

const FieldRegion* SAGenTestChecker::getFieldRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  const MemRegion *R = getMemRegionFromExpr(E, C);
  if (!R) return nullptr;
  R = R->getBaseRegion();
  // Typically we get an ElementRegion for array decays; walk up to FieldRegion.
  return findFieldRegionInRegion(R);
}

bool SAGenTestChecker::recordHasCountedByFlexArray(const RecordDecl *RD) {
  if (!RD) return false;
  for (const FieldDecl *F : RD->fields()) {
    if (!F) continue;
    const Type *T = F->getType().getTypePtrOrNull();
    if (!T) continue;
    if (isa<IncompleteArrayType>(T)) {
      if (F->hasAttr<CountedByAttr>())
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isFlexibleArrayWithCountedBy(const FieldDecl *FD) {
  if (!FD) return false;
  const Type *T = FD->getType().getTypePtrOrNull();
  if (!T) return false;
  if (!isa<IncompleteArrayType>(T))
    return false;
  // Require counted_by attribute.
  if (FD->hasAttr<CountedByAttr>())
    return true;
  // If attribute is missing, do not guess; avoid false positives.
  return false;
}

bool SAGenTestChecker::isCounterFieldForAnyCountedBy(const FieldDecl *FD) {
  if (!FD) return false;
  const RecordDecl *RD = FD->getParent();
  if (!RD) return false;

  bool HasAnyCB = false;
  for (const FieldDecl *F : RD->fields()) {
    if (!F) continue;
    if (!F->hasAttr<CountedByAttr>())
      continue;
    HasAnyCB = true;
    if (const auto *CBA = F->getAttr<CountedByAttr>()) {
      if (const Expr *E = getCountedByExprCompat(CBA)) {
        E = E->IgnoreParenCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
          if (const Decl *D = DRE->getDecl()) {
            if (D == FD)
              return true;
          }
        }
      }
    }
  }

  // Fallback: if we couldn't resolve the attribute target, be conservative
  // and only accept a well-known counter name when there exists any counted_by.
  if (HasAnyCB) {
    IdentifierInfo *II = FD->getIdentifier();
    if (II) {
      StringRef N = II->getName();
      if (N.equals("datalen"))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::reportAt(const Stmt *S, CheckerContext &C) const {
  if (!S) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Flex-array write before counter init (__counted_by)", N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportAtExpr(const Expr *E, CheckerContext &C) const {
  reportAt(cast<Stmt>(E), C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroingAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  const MemRegion *MR = Ret.getAsRegion();
  if (!MR) return;
  MR = getBaseOf(MR);
  if (!MR) return;

  // Mark this object as zero-initialized and its counter not set yet.
  State = State->set<ZeroInitObjMap>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R) return;

  const FieldRegion *FR = findFieldRegionInRegion(R);
  if (!FR) return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD) return;

  // If this is the counter field (for some counted_by flexible array), mark set.
  if (!isCounterFieldForAnyCountedBy(FD))
    return;

  const MemRegion *Base = getBaseOf(FR->getSuperRegion());
  if (!Base) return;

  ProgramStateRef State = C.getState();
  const bool *Tracked = State->get<ZeroInitObjMap>(Base);
  if (!Tracked) return;

  // Flip to true: counter is set.
  State = State->set<ZeroInitObjMap>(Base, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isMemWriteCall(Call, C))
    return;

  // Destination is arg0 for memcpy/memmove/memset/copy_from_user.
  const Expr *DestE = Call.getArgExpr(0);
  if (!DestE) return;

  const FieldRegion *FR = getFieldRegionFromExpr(DestE, C);
  if (!FR) return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD) return;

  if (!isFlexibleArrayWithCountedBy(FD))
    return;

  const MemRegion *Base = getBaseOf(FR->getSuperRegion());
  if (!Base) return;

  ProgramStateRef State = C.getState();
  const bool *CounterSet = State->get<ZeroInitObjMap>(Base);
  if (!CounterSet)
    return; // Not a tracked zero-initialized object.

  if (*CounterSet == false) {
    reportAtExpr(DestE, C);
    // Optionally set to true to avoid duplicate reports on same path.
    State = State->set<ZeroInitObjMap>(Base, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (IsLoad)
    return; // Only care about stores/writes.

  const MemRegion *R = Loc.getAsRegion();
  if (!R) return;

  const FieldRegion *FR = findFieldRegionInRegion(R);
  if (!FR) return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD) return;

  if (!isFlexibleArrayWithCountedBy(FD))
    return;

  const MemRegion *Base = getBaseOf(FR->getSuperRegion());
  if (!Base) return;

  ProgramStateRef State = C.getState();
  const bool *CounterSet = State->get<ZeroInitObjMap>(Base);
  if (!CounterSet)
    return;

  if (*CounterSet == false) {
    reportAt(S, C);
    // Avoid duplicate reports on same path.
    State = State->set<ZeroInitObjMap>(Base, true);
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect writes to __counted_by flexible arrays before initializing the counter (post-kzalloc/kcalloc)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
