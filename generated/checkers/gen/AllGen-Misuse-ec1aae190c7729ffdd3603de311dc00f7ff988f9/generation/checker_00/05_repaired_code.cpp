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
#include "clang/AST/Type.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Attr.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: tracks zero-initializing allocations and whether the
// length field that guards a counted_by flexible array has been set.
REGISTER_MAP_WITH_PROGRAMSTATE(KZeroAllocs, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(LenInitialized, const MemRegion *, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind,
        check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe flexible-array write", "Memory Safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isZeroAllocFn(const CallEvent &Call, CheckerContext &C);
      static bool isMemWriteFn(const CallEvent &Call, CheckerContext &C,
                               unsigned &DstIdx, unsigned &LenIdx);
      static const MemberExpr *getFlexArrayMEInExpr(const Expr *E);
      static const FieldDecl *getCountFieldForFlex(const FieldDecl *FlexFD);
      static const MemRegion *getBaseRegionFromME(const MemberExpr *ME, CheckerContext &C);

      static bool isFlexibleArrayField(const FieldDecl *FD);
      static bool isCountFieldForAnyFlexInRecord(const FieldDecl *FD);

      void markLenInitializedForRegion(const MemRegion *BaseR, CheckerContext &C) const;
      void reportFlexWriteBeforeLenInit(const Stmt *Trigger, CheckerContext &C) const;
};

// ------------------------ Helper Implementations ------------------------

bool SAGenTestChecker::isZeroAllocFn(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // Recognize common Linux zero-initializing allocators
  return ExprHasName(OE, "kzalloc", C) ||
         ExprHasName(OE, "kvzalloc", C) ||
         ExprHasName(OE, "kcalloc", C) ||
         ExprHasName(OE, "kzalloc_array", C) ||
         ExprHasName(OE, "devm_kzalloc", C) ||
         ExprHasName(OE, "devm_kcalloc", C) ||
         ExprHasName(OE, "devm_kzalloc_array", C);
}

bool SAGenTestChecker::isMemWriteFn(const CallEvent &Call, CheckerContext &C,
                                    unsigned &DstIdx, unsigned &LenIdx) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // libc-like memory writing APIs
  // memcpy(void *dst, const void *src, size_t n)
  if (ExprHasName(OE, "memcpy", C)) {
    DstIdx = 0; LenIdx = 2; return true;
  }
  // memmove(void *dst, const void *src, size_t n)
  if (ExprHasName(OE, "memmove", C)) {
    DstIdx = 0; LenIdx = 2; return true;
  }
  // memset(void *dst, int c, size_t n)
  if (ExprHasName(OE, "memset", C)) {
    DstIdx = 0; LenIdx = 2; return true;
  }

  return false;
}

const MemberExpr *SAGenTestChecker::getFlexArrayMEInExpr(const Expr *E) {
  if (!E) return nullptr;
  // Search downwards for a MemberExpr. Only return one if there are many.
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(E);
  if (!ME) return nullptr;

  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD) return nullptr;

  if (!isFlexibleArrayField(FD))
    return nullptr;

  return ME;
}

bool SAGenTestChecker::isFlexibleArrayField(const FieldDecl *FD) {
  if (!FD) return false;
  QualType FT = FD->getType();

  // Flexible array members in C are represented as IncompleteArrayType.
  if (!FT->isIncompleteArrayType())
    return false;

  return true;
}

const FieldDecl *SAGenTestChecker::getCountFieldForFlex(const FieldDecl *FlexFD) {
  if (!FlexFD) return nullptr;
  if (!isFlexibleArrayField(FlexFD))
    return nullptr;

  // Only handle fields explicitly annotated with counted_by.
  if (const auto *CBA = FlexFD->getAttr<CountedByAttr>()) {
    // In Clang 18, CountedByAttr stores the identifier of the count field.
    if (IdentifierInfo *II = CBA->getCountedByField()) {
      const RecordDecl *RD = FlexFD->getParent();
      if (!RD) return nullptr;
      for (const FieldDecl *FD : RD->fields()) {
        if (FD->getIdentifier() == II)
          return FD;
      }
    }
  }
  return nullptr;
}

const MemRegion *SAGenTestChecker::getBaseRegionFromME(const MemberExpr *ME, CheckerContext &C) {
  if (!ME) return nullptr;

  // Use the whole MemberExpr to get a region referring to the field, then
  // collapse to the base region representing the underlying object.
  const MemRegion *R = getMemRegionFromExpr(ME, C);
  if (!R) return nullptr;
  return R->getBaseRegion();
}

bool SAGenTestChecker::isCountFieldForAnyFlexInRecord(const FieldDecl *FD) {
  if (!FD) return false;
  const RecordDecl *RD = FD->getParent();
  if (!RD) return false;

  for (const FieldDecl *F : RD->fields()) {
    if (!isFlexibleArrayField(F))
      continue;
    if (const FieldDecl *Counter = getCountFieldForFlex(F)) {
      if (Counter == FD)
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::markLenInitializedForRegion(const MemRegion *BaseR, CheckerContext &C) const {
  if (!BaseR) return;
  ProgramStateRef State = C.getState();
  State = State->set<LenInitialized>(BaseR, true);
  C.addTransition(State);
}

void SAGenTestChecker::reportFlexWriteBeforeLenInit(const Stmt *Trigger, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "write to counted_by flexible array before updating length field", N);
  if (Trigger)
    R->addRange(Trigger->getSourceRange());
  C.emitReport(std::move(R));
}

// ------------------------ Checker Callbacks ------------------------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroAllocFn(Call, C))
    return;

  // Mark the returned allocation object as zero-initialized and its
  // length field as not-yet-initialized.
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return;
  const CallExpr *CE = dyn_cast<CallExpr>(OE);
  if (!CE) return;

  const MemRegion *MR = getMemRegionFromExpr(CE, C);
  if (!MR) return;

  MR = MR->getBaseRegion();
  if (!MR) return;

  ProgramStateRef State = C.getState();
  State = State->set<KZeroAllocs>(MR, true);
  State = State->set<LenInitialized>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned DstIdx = 0, LenIdx = 0;
  if (!isMemWriteFn(Call, C, DstIdx, LenIdx))
    return;

  if (DstIdx >= Call.getNumArgs())
    return;

  const Expr *DstE = Call.getArgExpr(DstIdx);
  if (!DstE) return;

  // Are we writing into a flexible array member?
  const MemberExpr *ME = getFlexArrayMEInExpr(DstE);
  if (!ME) return;

  const auto *FlexFD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FlexFD) return;

  // Only consider flexible arrays that are annotated with counted_by.
  const FieldDecl *CountFD = getCountFieldForFlex(FlexFD);
  if (!CountFD)
    return;

  // Identify the underlying object region that contains the flexible array.
  const MemRegion *BaseR = getBaseRegionFromME(ME, C);
  if (!BaseR) return;

  BaseR = BaseR->getBaseRegion();
  ProgramStateRef State = C.getState();

  // Only warn if we know the object is zero-initialized (kzalloc-family).
  const bool *Zeroed = State->get<KZeroAllocs>(BaseR);
  if (!Zeroed || !*Zeroed)
    return;

  // If the length field hasn't been written yet, this is the bug.
  const bool *Init = State->get<LenInitialized>(BaseR);
  if (Init && *Init)
    return;

  // Optionally suppress zero-length writes.
  if (LenIdx < Call.getNumArgs()) {
    const Expr *LenE = Call.getArgExpr(LenIdx);
    llvm::APSInt LenVal;
    if (LenE && EvaluateExprToInt(LenVal, LenE, C)) {
      if (LenVal == 0)
        return;
    }
  }

  reportFlexWriteBeforeLenInit(Call.getOriginExpr(), C);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Detect "obj->len = ..." when 'len' is the counted_by field for some flexible array.
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  const FieldRegion *FR = dyn_cast<FieldRegion>(R);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  // If this field is the counter for any counted_by flexible array in the same record
  // then mark the base object as having its length initialized.
  if (!isCountFieldForAnyFlexInRecord(FD))
    return;

  const MemRegion *BaseR = FR->getBaseRegion();
  if (!BaseR)
    return;

  markLenInitializedForRegion(BaseR, C);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Optional: detect direct stores into obj->flex[i] before len is set.
  if (IsLoad)
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  // Walk up to find a FieldRegion that corresponds to a flexible array member.
  const SubRegion *SR = dyn_cast<SubRegion>(R);
  const FieldRegion *FlexFR = nullptr;
  while (SR) {
    if (const auto *FR = dyn_cast<FieldRegion>(SR)) {
      const FieldDecl *FD = FR->getDecl();
      if (FD && isFlexibleArrayField(FD) && getCountFieldForFlex(FD)) {
        FlexFR = FR;
        break;
      }
    }
    SR = dyn_cast<SubRegion>(SR->getSuperRegion());
  }

  if (!FlexFR)
    return;

  const MemRegion *BaseR = FlexFR->getBaseRegion();
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();

  const bool *Zeroed = State->get<KZeroAllocs>(BaseR);
  if (!Zeroed || !*Zeroed)
    return;

  const bool *Init = State->get<LenInitialized>(BaseR);
  if (Init && *Init)
    return;

  reportFlexWriteBeforeLenInit(S, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect writes to __counted_by flexible arrays before updating their length field after kzalloc-like allocations",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
