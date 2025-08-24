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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/ADT/ImmutableSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track zero-initialized heap objects (from zeroing allocators).
REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitObjs, const MemRegion*)

// Program state: for each base object, track which counter fields are initialized.
using FieldSet = llvm::ImmutableSet<const FieldDecl *>;
REGISTER_MAP_WITH_PROGRAMSTATE(CounterInitSet, const MemRegion*, FieldSet)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Flexible-array before counter init", "Memory")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isCalleeOneOf(const CallEvent &Call, CheckerContext &C,
                                std::initializer_list<StringRef> Names);
      static bool isZeroingAllocator(const CallEvent &Call, CheckerContext &C);
      static bool isMemCpyLike(const CallEvent &Call, CheckerContext &C);

      static const FieldRegion *getFieldRegionFromExpr(const Expr *E, CheckerContext &C);
      static const MemRegion *getRootBaseRegion(const MemRegion *R);

      static const FieldDecl *getCountedByCounterFD(const FieldDecl *FAFld);
      static bool isCountedByCounterField(const FieldDecl *FD);

      static ProgramStateRef addCounterInit(ProgramStateRef State, const MemRegion *Base,
                                            const FieldDecl *FD);

      void reportEarlyFAccess(const CallEvent &Call, const Expr *Dst, CheckerContext &C) const;
};

// --------------------- Helper implementations ---------------------

bool SAGenTestChecker::isCalleeOneOf(const CallEvent &Call, CheckerContext &C,
                                     std::initializer_list<StringRef> Names) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  for (StringRef N : Names) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isZeroingAllocator(const CallEvent &Call, CheckerContext &C) {
  // A small set of common zeroing allocators in the kernel
  return isCalleeOneOf(Call, C, {
      "kzalloc", "__kzalloc", "kvzalloc", "kzalloc_node", "kcalloc", "devm_kzalloc"
  });
}

bool SAGenTestChecker::isMemCpyLike(const CallEvent &Call, CheckerContext &C) {
  return isCalleeOneOf(Call, C, {
      "memcpy", "__memcpy", "__builtin_memcpy",
      "memmove", "__memmove", "__builtin_memmove"
  });
}

const FieldRegion *SAGenTestChecker::getFieldRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;

  // Walk up through subregions to find the field region (e.g., event->data).
  const MemRegion *Cur = MR;
  while (Cur && !isa<FieldRegion>(Cur)) {
    const SubRegion *SR = dyn_cast<SubRegion>(Cur);
    if (!SR)
      break;
    Cur = SR->getSuperRegion();
  }
  return dyn_cast_or_null<FieldRegion>(Cur);
}

const MemRegion *SAGenTestChecker::getRootBaseRegion(const MemRegion *R) {
  if (!R)
    return nullptr;
  // Always use getBaseRegion() to fetch the ultimate base region.
  return R->getBaseRegion();
}

const FieldDecl *SAGenTestChecker::getCountedByCounterFD(const FieldDecl *FAFld) {
  if (!FAFld)
    return nullptr;
  // The flexible-array field should carry the counted_by attribute.
  if (const auto *A = FAFld->getAttr<CountedByAttr>()) {
    // CountedByAttr holds a direct reference to the counter FieldDecl
    if (const FieldDecl *FD = A->getCountedBy())
      return FD;
  }
  return nullptr;
}

bool SAGenTestChecker::isCountedByCounterField(const FieldDecl *FD) {
  if (!FD)
    return false;
  const RecordDecl *RD = FD->getParent();
  if (!RD)
    return false;

  for (const FieldDecl *F : RD->fields()) {
    QualType FT = F->getType();
    if (!FT.isNull() && FT->isIncompleteArrayType()) {
      if (const FieldDecl *Counter = getCountedByCounterFD(F)) {
        if (Counter == FD)
          return true;
      }
    }
  }
  return false;
}

ProgramStateRef SAGenTestChecker::addCounterInit(ProgramStateRef State,
                                                 const MemRegion *Base,
                                                 const FieldDecl *FD) {
  if (!State || !Base || !FD)
    return State;

  FieldSet::Factory &F = State->get_context<FieldSet>();
  const FieldSet *Existing = State->get<CounterInitSet>(Base);
  FieldSet S = Existing ? *Existing : F.getEmptySet();
  S = F.add(S, FD);
  return State->set<CounterInitSet>(Base, S);
}

void SAGenTestChecker::reportEarlyFAccess(const CallEvent &Call, const Expr *Dst,
                                          CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "flexible-array accessed before initializing its __counted_by counter", N);
  if (const Stmt *OS = Call.getOriginExpr())
    R->addRange(OS->getSourceRange());
  if (Dst)
    R->addRange(Dst->getSourceRange());
  C.emitReport(std::move(R));
}

// --------------------- Checker callbacks ---------------------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroingAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();

  // Try to obtain the region of the allocated object through the return value.
  const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
  if (!RetReg) {
    const Expr *E = Call.getOriginExpr();
    if (E)
      RetReg = getMemRegionFromExpr(E, C);
  }
  if (!RetReg)
    return;

  // Always get the base region to track the heap object.
  const MemRegion *Base = getRootBaseRegion(RetReg);
  if (!Base)
    return;

  State = State->add<ZeroInitObjs>(Base);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Only interested in assignments to counter fields.
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return;

  const Expr *LHSStripped = LHS->IgnoreParenCasts();
  const auto *ME = dyn_cast<MemberExpr>(LHSStripped);
  if (!ME)
    return;

  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return;

  // Confirm that the field being assigned is a counter for a flexible array with __counted_by.
  if (!isCountedByCounterField(FD))
    return;

  // Find the base region for the object containing this field.
  const MemRegion *LHSReg = getMemRegionFromExpr(LHS, C);
  if (!LHSReg)
    return;

  const FieldRegion *FR = nullptr;
  // Walk up to find the FieldRegion for this member
  const MemRegion *Cur = LHSReg;
  while (Cur && !isa<FieldRegion>(Cur)) {
    const SubRegion *SR = dyn_cast<SubRegion>(Cur);
    if (!SR)
      break;
    Cur = SR->getSuperRegion();
  }
  FR = dyn_cast_or_null<FieldRegion>(Cur);
  if (!FR)
    return;

  const MemRegion *Base = getRootBaseRegion(FR->getSuperRegion());
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  State = addCounterInit(State, Base, FD);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isMemCpyLike(Call, C))
    return;

  // Destination is arg0 for memcpy/memmove-like functions.
  const Expr *DstE = Call.getArgExpr(0);
  if (!DstE)
    return;

  const FieldRegion *DstFR = getFieldRegionFromExpr(DstE, C);
  if (!DstFR)
    return;

  const FieldDecl *FAFld = DstFR->getDecl();
  if (!FAFld)
    return;

  // Destination must be a flexible-array member (incomplete array type).
  QualType DTy = FAFld->getType();
  if (DTy.isNull() || !DTy->isIncompleteArrayType())
    return;

  // Must be annotated with __counted_by.
  const FieldDecl *CounterFD = getCountedByCounterFD(FAFld);
  if (!CounterFD)
    return;

  const MemRegion *Base = getRootBaseRegion(DstFR->getSuperRegion());
  if (!Base)
    return;

  ProgramStateRef State = C.getState();

  // Only warn if the object is known zero-initialized (kzalloc family, etc.).
  if (!State->contains<ZeroInitObjs>(Base))
    return;

  // If length is provably zero, skip.
  llvm::APSInt LenVal;
  if (EvaluateExprToInt(LenVal, Call.getArgExpr(2), C)) {
    if (LenVal == 0)
      return;
  }

  // Check if the counter has been initialized on this path.
  const FieldSet *Initialized = State->get<CounterInitSet>(Base);
  bool CounterInit = false;
  if (Initialized && Initialized->contains(CounterFD))
    CounterInit = true;

  if (!CounterInit) {
    reportEarlyFAccess(Call, DstE, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects accesses to __counted_by flexible-array members before initializing their counters",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
