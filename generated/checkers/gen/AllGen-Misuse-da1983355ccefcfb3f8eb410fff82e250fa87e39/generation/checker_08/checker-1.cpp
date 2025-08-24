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

// Program state: track zero-initialized allocated objects (kzalloc/kcalloc/kvcalloc/devm_kzalloc)
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitObjMap, const MemRegion*, char)
// Program state: track which specific field-regions have been initialized via assignment
REGISTER_SET_WITH_PROGRAMSTATE(InitializedCountFieldSet, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker< eval::Call,
                    check::PostCall,
                    check::PreCall,
                    check::Bind > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Write to counted_by FAM before count init", "Memory")) {}

      bool evalCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      bool isZeroInitAlloc(const CallEvent &Call, CheckerContext &C) const;
      bool isMemcpyLike(const CallEvent &Call, CheckerContext &C) const;
      const FieldRegion *getDestFieldRegion(const Expr *DestArg, CheckerContext &C) const;
      const MemRegion *getObjectBaseRegion(const MemRegion *R) const;
      bool isFlexibleArrayMember(const FieldDecl *FD) const;
      const FieldDecl *getCountedByField(const FieldDecl *FAMFD) const;
      bool sizeIsNonZero(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::isZeroInitAlloc(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Zero-initializing allocators we care about
  return ExprHasName(Origin, "kzalloc", C) ||
         ExprHasName(Origin, "kcalloc", C) ||
         ExprHasName(Origin, "kvcalloc", C) ||
         ExprHasName(Origin, "devm_kzalloc", C);
}

bool SAGenTestChecker::isMemcpyLike(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Common memcpy-like APIs in the kernel
  return ExprHasName(Origin, "memcpy", C) ||
         ExprHasName(Origin, "__memcpy", C) ||
         ExprHasName(Origin, "memmove", C);
}

const MemRegion *SAGenTestChecker::getObjectBaseRegion(const MemRegion *R) const {
  if (!R)
    return nullptr;
  return R->getBaseRegion();
}

bool SAGenTestChecker::isFlexibleArrayMember(const FieldDecl *FD) const {
  if (!FD)
    return false;
  QualType FT = FD->getType();
  return FT->isIncompleteArrayType();
}

const FieldDecl *SAGenTestChecker::getCountedByField(const FieldDecl *FAMFD) const {
  if (!FAMFD)
    return nullptr;

  if (const auto *A = FAMFD->getAttr<CountedByAttr>()) {
    // In Clang 18, the resolved counted_by target is available as a FieldDecl.
    if (const FieldDecl *FD = A->getCountedByField())
      return FD;
  }
  // If no attribute or cannot resolve, be conservative and do not warn.
  return nullptr;
}

const FieldRegion *SAGenTestChecker::getDestFieldRegion(const Expr *DestArg, CheckerContext &C) const {
  if (!DestArg)
    return nullptr;

  // Try directly on the expression
  if (const MemRegion *MR = getMemRegionFromExpr(DestArg, C)) {
    // Walk up to find a FieldRegion
    const MemRegion *Cur = MR;
    while (Cur && !isa<FieldRegion>(Cur)) {
      if (const auto *SR = dyn_cast<SubRegion>(Cur))
        Cur = SR->getSuperRegion();
      else
        break;
    }
    if (const auto *FR = dyn_cast_or_null<FieldRegion>(Cur))
      return FR;
  }

  // Try to locate a MemberExpr within the destination expression
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(DestArg)) {
    if (const MemRegion *MR2 = getMemRegionFromExpr(ME, C)) {
      const MemRegion *Cur = MR2;
      while (Cur && !isa<FieldRegion>(Cur)) {
        if (const auto *SR = dyn_cast<SubRegion>(Cur))
          Cur = SR->getSuperRegion();
        else
          break;
      }
      if (const auto *FR = dyn_cast_or_null<FieldRegion>(Cur))
        return FR;
    }
  }

  return nullptr;
}

bool SAGenTestChecker::sizeIsNonZero(const CallEvent &Call, CheckerContext &C) const {
  if (Call.getNumArgs() < 3)
    return true;
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, Call.getArgExpr(2), C)) {
    // If the size can be evaluated, return whether it's non-zero
    return EvalRes != 0;
  }
  // If unknown, assume non-zero (to avoid missing the bug).
  return true;
}

bool SAGenTestChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  // Model zero-initializing allocators to ensure we have a symbolic heap region
  if (!isZeroInitAlloc(Call, C))
    return false;

  const Expr *Origin = Call.getOriginExpr();
  const auto *CE = dyn_cast_or_null<CallExpr>(Origin);
  if (!CE)
    return false;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  unsigned Count = C.blockCount();
  const LocationContext *LCtx = C.getPredecessor()->getLocationContext();

  DefinedSVal RetVal = SVB.getConjuredHeapSymbolVal(CE, LCtx, Count).castAs<DefinedSVal>();
  State = State->BindExpr(CE, LCtx, RetVal);

  if (const MemRegion *R = RetVal.getAsRegion()) {
    const MemRegion *Base = getObjectBaseRegion(R);
    if (Base) {
      State = State->set<ZeroInitObjMap>(Base, 1);
    }
  }

  if (State)
    C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // As a fallback (if evalCall didn't run), record zero-initialized allocations
  if (!isZeroInitAlloc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *R = Call.getReturnValue().getAsRegion();
  if (!R)
    return;

  const MemRegion *Base = getObjectBaseRegion(R);
  if (!Base)
    return;

  State = State->set<ZeroInitObjMap>(Base, 1);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  // Track when a field in a zero-initialized object is assigned (initialized)
  const MemRegion *Reg = Loc.getAsRegion();
  if (!Reg)
    return;

  const auto *FR = dyn_cast<FieldRegion>(Reg);
  if (!FR)
    return;

  const MemRegion *Base = getObjectBaseRegion(FR);
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  // Only track fields for zero-initialized heap objects
  if (State->get<ZeroInitObjMap>(Base)) {
    State = State->add<InitializedCountFieldSet>(FR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isMemcpyLike(Call, C))
    return;

  // Destination arg should be arg 0
  if (Call.getNumArgs() < 1)
    return;

  const Expr *DestExpr = Call.getArgExpr(0);
  const FieldRegion *DestFR = getDestFieldRegion(DestExpr, C);
  if (!DestFR)
    return;

  const FieldDecl *DestFD = DestFR->getDecl();
  if (!isFlexibleArrayMember(DestFD))
    return;

  // Must be an annotated counted_by FAM
  const FieldDecl *CountFD = getCountedByField(DestFD);
  if (!CountFD)
    return;

  const MemRegion *Base = getObjectBaseRegion(DestFR);
  if (!Base)
    return;

  ProgramStateRef State = C.getState();

  // Only consider zero-initialized objects (kzalloc/kcalloc/kvcalloc/devm_kzalloc)
  if (!State->get<ZeroInitObjMap>(Base))
    return;

  // Build the FieldRegion for the count field on the same base object
  SValBuilder &SVB = C.getSValBuilder();
  SVal BaseLoc = loc::MemRegionVal(Base);
  SVal CountLVal = SVB.getLValueField(CountFD, BaseLoc);
  const MemRegion *CountFR = CountLVal.getAsRegion();
  if (!CountFR)
    return;

  // If the count field was initialized before, do not warn
  if (State->contains<InitializedCountFieldSet>(CountFR))
    return;

  // Avoid warning for known-zero size copies
  if (!sizeIsNonZero(Call, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Write to __counted_by flexible array before initializing its count field", N);
  if (DestExpr)
    R->addRange(DestExpr->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects writes to __counted_by flexible arrays before initializing the count field on zero-initialized objects",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
