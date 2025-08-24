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
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitObjMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(CounterInitBaseMap, const MemRegion*, bool)

namespace {
class SAGenTestChecker
    : public Checker<
          check::PostCall,
          check::PreCall,
          check::Bind
      > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Write to flexible array before setting its __counted_by counter",
                       "Memory Safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool isZeroingAlloc(const CallEvent &Call, CheckerContext &C);
  static bool isWriteToFirstParamFunction(const CallEvent &Call, CheckerContext &C);

  static const MemRegion *getBaseRegionFromMember(const MemberExpr *ME, CheckerContext &C);

  static bool fieldIsFlexibleArray(const FieldDecl *FD);
  static bool fieldHasCountedBy(const FieldDecl *FD);

  static const FieldDecl *getCountedByCounterField(const FieldDecl *FAMField);
  static bool isCounterForAnyCountedByField(const FieldDecl *FD, CheckerContext &C);

  void reportBeforeCounterInit(const CallEvent &Call, const MemberExpr *DstME,
                               const FieldDecl *FAMField, CheckerContext &C) const;
};

// Determine if a call is a zero-initializing allocation.
bool SAGenTestChecker::isZeroingAlloc(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Common kernel zeroing allocators
  if (ExprHasName(OE, "kzalloc", C)) return true;
  if (ExprHasName(OE, "kcalloc", C)) return true;
  if (ExprHasName(OE, "kzalloc_array", C)) return true;
  if (ExprHasName(OE, "kvzalloc", C)) return true;
  if (ExprHasName(OE, "vzalloc", C)) return true;

  // Device-managed variants (optional, but safe to recognize)
  if (ExprHasName(OE, "devm_kzalloc", C)) return true;
  if (ExprHasName(OE, "devm_kcalloc", C)) return true;

  return false;
}

// Functions that (likely) write to their first parameter.
bool SAGenTestChecker::isWriteToFirstParamFunction(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Keep minimal but sufficient for the target bug
  if (ExprHasName(OE, "memcpy", C)) return true;
  if (ExprHasName(OE, "__memcpy", C)) return true;
  if (ExprHasName(OE, "memmove", C)) return true;
  if (ExprHasName(OE, "copy_from_user", C)) return true;

  return false;
}

const MemRegion *SAGenTestChecker::getBaseRegionFromMember(const MemberExpr *ME, CheckerContext &C) {
  if (!ME)
    return nullptr;

  // Important: do not IgnoreImplicit() before calling getMemRegionFromExpr
  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR)
    return nullptr;

  MR = MR->getBaseRegion();
  return MR;
}

bool SAGenTestChecker::fieldIsFlexibleArray(const FieldDecl *FD) {
  if (!FD)
    return false;
  QualType QT = FD->getType();
  if (QT.isNull())
    return false;

  // Flexible array members are incomplete arrays in C
  return QT->isIncompleteArrayType();
}

bool SAGenTestChecker::fieldHasCountedBy(const FieldDecl *FD) {
  if (!FD)
    return false;
  return FD->hasAttr<CountedByAttr>();
}

// Try to resolve the FieldDecl referenced by the counted_by attribute.
const FieldDecl *SAGenTestChecker::getCountedByCounterField(const FieldDecl *FAMField) {
  if (!FAMField)
    return nullptr;

  const auto *Attr = FAMField->getAttr<CountedByAttr>();
  if (!Attr)
    return nullptr;

  // In Clang-18, CountedByAttr stores an identifier of the counter field.
  if (const IdentifierInfo *II = Attr->getCountedBy()) {
    const RecordDecl *RD = FAMField->getParent();
    if (!RD)
      return nullptr;
    for (const FieldDecl *F : RD->fields()) {
      if (F->getIdentifier() == II)
        return F;
    }
  }
  return nullptr;
}

// Check whether FD is the counter for any counted_by FAM field within the same record.
bool SAGenTestChecker::isCounterForAnyCountedByField(const FieldDecl *FD, CheckerContext &C) {
  if (!FD)
    return false;

  const RecordDecl *RD = FD->getParent();
  if (!RD)
    return false;

  for (const FieldDecl *F : RD->fields()) {
    if (!fieldHasCountedBy(F))
      continue;

    // Resolve the FieldDecl from the attribute and compare.
    if (const FieldDecl *CounterFD = getCountedByCounterField(F)) {
      if (CounterFD == FD)
        return true;
      continue;
    }
  }
  return false;
}

void SAGenTestChecker::reportBeforeCounterInit(const CallEvent &Call, const MemberExpr *DstME,
                                               const FieldDecl *FAMField, CheckerContext &C) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "Write to flexible array before setting its __counted_by counter";
  if (FAMField) {
    Msg += " (";
    Msg += FAMField->getName();
    Msg += ")";
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (const Expr *OE = Call.getOriginExpr())
    R->addRange(OE->getSourceRange());
  if (DstME)
    R->addRange(DstME->getSourceRange());
  C.emitReport(std::move(R));
}

// Mark zero-initialized objects when returned from zeroing allocators.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroingAlloc(Call, C))
    return;

  ProgramStateRef State = C.getState();

  SVal Ret = Call.getReturnValue();
  const MemRegion *MR = Ret.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->set<ZeroInitObjMap>(MR, true);
  C.addTransition(State);
}

// Detect writes to FAM with counted_by before counter init.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isWriteToFirstParamFunction(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *DstArgE = Call.getArgExpr(0);
  if (!DstArgE)
    return;

  // Try to find a MemberExpr inside the destination argument, e.g., event->data
  const MemberExpr *DstME = dyn_cast<MemberExpr>(DstArgE->IgnoreParenCasts());
  if (!DstME)
    DstME = findSpecificTypeInChildren<MemberExpr>(DstArgE);
  if (!DstME)
    return;

  const ValueDecl *VD = DstME->getMemberDecl();
  const FieldDecl *FAMField = dyn_cast_or_null<FieldDecl>(VD);
  if (!FAMField)
    return;

  // Must be a flexible-array member
  if (!fieldIsFlexibleArray(FAMField))
    return;

  // Must have __counted_by attribute
  if (!fieldHasCountedBy(FAMField))
    return;

  // Get the base object region holding this field, e.g., 'event'
  const MemRegion *BaseR = getBaseRegionFromMember(DstME, C);
  if (!BaseR)
    return;

  // Only warn for objects we know are zero-initialized by kzalloc/kcalloc/...
  ProgramStateRef State = C.getState();
  const bool *IsZeroed = State->get<ZeroInitObjMap>(BaseR);
  if (!IsZeroed || !*IsZeroed)
    return;

  // Has the (relevant) counter field been initialized?
  const bool *CounterInit = State->get<CounterInitBaseMap>(BaseR);
  if (CounterInit && *CounterInit)
    return;

  // Not initialized yet: report
  reportBeforeCounterInit(Call, DstME, FAMField, C);
}

// Observe assignments to fields that are counters of counted_by flexible arrays.
// When we see e.g. "obj->len = n;", mark the base object as having initialized
// the counter.
void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  const FieldRegion *FR = dyn_cast<FieldRegion>(R->getBaseRegion()->getAs<SubRegion>() ? R : R);
  if (!FR)
    FR = dyn_cast<FieldRegion>(R);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  // Only consider fields that are counters for a counted_by FAM in this record.
  if (!isCounterForAnyCountedByField(FD, C))
    return;

  // Mark the base object as having its counter initialized.
  const MemRegion *BaseR = FR->getSuperRegion();
  if (!BaseR)
    return;

  BaseR = BaseR->getBaseRegion();
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<CounterInitBaseMap>(BaseR, true);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects writes to __counted_by flexible arrays before initializing their counter (after zeroing alloc)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
