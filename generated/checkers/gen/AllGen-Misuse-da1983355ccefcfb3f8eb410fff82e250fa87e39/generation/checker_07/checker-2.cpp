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
#include "clang/AST/Decl.h"
#include "clang/AST/Attr.h"
#include "llvm/ADT/ImmutableSet.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states

// 1) Track zero-initialized heap objects (returned by kzalloc/kcalloc/devm_kzalloc/devm_kcalloc).
REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitedObjs, const MemRegion*)

// 2) Track fields written per object base region.
using FieldSetTy = llvm::ImmutableSet<const FieldDecl *>;
REGISTER_MAP_WITH_PROGRAMSTATE(FieldsWrittenMap, const MemRegion*, FieldSetTy)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Counted-by flexible array write before size init", "Memory safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static const MemRegion *getRootBaseRegion(const MemRegion *R);
      static const FieldRegion *getFieldRegionFromPointerRegion(const MemRegion *R);

      static bool isZeroAlloc(const CallEvent &Call, CheckerContext &C);
      static bool isMemcpyLike(const CallEvent &Call, unsigned &DstIdx, unsigned &SizeIdx, CheckerContext &C);

      static bool famHasCountedBy(const FieldDecl *FamFD, const FieldDecl* &CountFD);

      static bool wasFieldWritten(const MemRegion *Base, const FieldDecl *FD, ProgramStateRef State);
      static ProgramStateRef addFieldWritten(const MemRegion *Base, const FieldDecl *FD, ProgramStateRef State);

      void reportEarlyFamWrite(const CallEvent &Call, unsigned DstIdx, CheckerContext &C) const;
};

//
// Helper function implementations
//

const MemRegion *SAGenTestChecker::getRootBaseRegion(const MemRegion *R) {
  if (!R) return nullptr;
  return R->getBaseRegion();
}

const FieldRegion *SAGenTestChecker::getFieldRegionFromPointerRegion(const MemRegion *R) {
  if (!R) return nullptr;

  // Do not call getBaseRegion() here; we need the specific FieldRegion if present.
  const MemRegion *Cur = R;

  if (const auto *ER = dyn_cast<ElementRegion>(Cur)) {
    Cur = ER->getSuperRegion();
  }

  if (const auto *FR = dyn_cast<FieldRegion>(Cur)) {
    return FR;
  }

  // Sometimes there might be more wrappers; unwrap a bit more cautiously.
  if (const auto *SR = dyn_cast<SubRegion>(Cur)) {
    const MemRegion *Sup = SR->getSuperRegion();
    if (const auto *ER2 = dyn_cast_or_null<ElementRegion>(Sup)) {
      const MemRegion *Sup2 = ER2->getSuperRegion();
      if (const auto *FR2 = dyn_cast_or_null<FieldRegion>(Sup2))
        return FR2;
    }
    if (const auto *FR2 = dyn_cast_or_null<FieldRegion>(Sup))
      return FR2;
  }

  return nullptr;
}

bool SAGenTestChecker::isZeroAlloc(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;

  // Use ExprHasName per guidance.
  return ExprHasName(Origin, "kzalloc", C) ||
         ExprHasName(Origin, "kcalloc", C) ||
         ExprHasName(Origin, "devm_kzalloc", C) ||
         ExprHasName(Origin, "devm_kcalloc", C);
}

bool SAGenTestChecker::isMemcpyLike(const CallEvent &Call, unsigned &DstIdx, unsigned &SizeIdx, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;

  if (ExprHasName(Origin, "memcpy", C) || ExprHasName(Origin, "memmove", C)) {
    DstIdx = 0;
    SizeIdx = 2;
    return true;
  }
  return false;
}

bool SAGenTestChecker::famHasCountedBy(const FieldDecl *FamFD, const FieldDecl* &CountFD) {
  CountFD = nullptr;
  if (!FamFD) return false;

  QualType FT = FamFD->getType();
  if (!FT->isIncompleteArrayType())
    return false;

  if (const auto *A = FamFD->getAttr<CountedByAttr>()) {
    // Counted_by attr should contain an expression naming the count field.
    if (const Expr *E = A->getExpr()) {
      E = E->IgnoreParenCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (const auto *FD = dyn_cast<FieldDecl>(DRE->getDecl())) {
          CountFD = FD;
          return true;
        }
      }
      if (const auto *ME = dyn_cast<MemberExpr>(E)) {
        if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          CountFD = FD;
          return true;
        }
      }
    }
  }

  return false;
}

bool SAGenTestChecker::wasFieldWritten(const MemRegion *Base, const FieldDecl *FD, ProgramStateRef State) {
  if (!Base || !FD || !State) return false;
  const FieldSetTy *S = State->get<FieldsWrittenMap>(Base);
  if (!S) return false;
  return S->contains(FD);
}

ProgramStateRef SAGenTestChecker::addFieldWritten(const MemRegion *Base, const FieldDecl *FD, ProgramStateRef State) {
  if (!Base || !FD || !State) return State;
  FieldSetTy::Factory &F = State->getStateManager().get_context<FieldSetTy>();
  FieldSetTy Current = State->get<FieldsWrittenMap>(Base) ? *State->get<FieldsWrittenMap>(Base) : F.getEmptySet();
  FieldSetTy NewSet = F.add(Current, FD);
  return State->set<FieldsWrittenMap>(Base, NewSet);
}

//
// Checker callbacks
//

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroAlloc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
  if (!RetReg)
    return;

  // Track zero-initialized object region (base).
  const MemRegion *Base = getRootBaseRegion(RetReg);
  if (!Base)
    return;

  State = State->add<ZeroInitedObjs>(Base);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *Reg = Loc.getAsRegion();
  if (!Reg)
    return;

  // We only care about writes to fields.
  if (const auto *FR = dyn_cast<FieldRegion>(Reg)) {
    const FieldDecl *FD = FR->getDecl();
    const MemRegion *Base = getRootBaseRegion(FR);
    if (!FD || !Base)
      return;

    ProgramStateRef State = C.getState();
    State = addFieldWritten(Base, FD, State);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned DstIdx = 0, SizeIdx = 0;
  if (!isMemcpyLike(Call, DstIdx, SizeIdx, C))
    return;

  const Expr *DstE = Call.getArgExpr(DstIdx);
  if (!DstE)
    return;

  const MemRegion *DstReg = C.getSVal(DstE).getAsRegion();
  if (!DstReg)
    return;

  // Extract the field region corresponding to a flexible array member, if any.
  const FieldRegion *FR = getFieldRegionFromPointerRegion(DstReg);
  if (!FR)
    return;

  const FieldDecl *FamFD = FR->getDecl();
  if (!FamFD)
    return;

  // Must be a flexible array (incomplete array type).
  if (!FamFD->getType()->isIncompleteArrayType())
    return;

  // Must have __counted_by attribute to reduce false positives.
  const FieldDecl *CountFD = nullptr;
  if (!famHasCountedBy(FamFD, CountFD))
    return;

  // Destination base object must be known zero-initialized.
  const MemRegion *Base = getRootBaseRegion(FR);
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<ZeroInitedObjs>(Base))
    return;

  // If size is definitely zero, skip.
  if (SizeIdx < Call.getNumArgs()) {
    llvm::APSInt SizeVal;
    const Expr *SizeE = Call.getArgExpr(SizeIdx);
    if (SizeE && EvaluateExprToInt(SizeVal, SizeE, C) && SizeVal.isZero())
      return;
  }

  // If the count field was written earlier on this path, it's okay.
  if (wasFieldWritten(Base, CountFD, State))
    return;

  // Report: writing into counted_by FAM before setting its length.
  reportEarlyFamWrite(Call, DstIdx, C);
}

void SAGenTestChecker::reportEarlyFamWrite(const CallEvent &Call, unsigned DstIdx, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "memcpy to counted_by flexible array before setting its length", N);

  if (const Expr *ArgE = Call.getArgExpr(DstIdx))
    R->addRange(ArgE->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect memcpy/memmove into __counted_by flexible arrays before initializing the count field on zero-initialized objects",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
