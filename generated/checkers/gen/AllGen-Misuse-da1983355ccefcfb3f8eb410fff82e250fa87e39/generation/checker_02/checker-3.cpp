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
#include "clang/AST/Type.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitObjs, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(CountFieldInitMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        eval::Call,        // to model zeroing allocators
        check::PreCall,    // to check mem* calls before they execute
        check::Bind        // to notice writes to count fields
      > {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
             "Write to counted flexible array before count is set",
             "Memory Safety")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool isZeroingAllocator(const CallEvent &Call, CheckerContext &C);
  static bool isMemOpCall(const CallEvent &Call, unsigned &DstParamIndex, CheckerContext &C);
  static const MemberExpr* getMemberExprFromArg(const Expr *Arg, CheckerContext &C);
  static bool isFlexibleArrayField(const FieldDecl *FD);
  static const FieldDecl* getCountedByField(const FieldDecl *FlexibleArrayFD);
  static const MemRegion* getBaseObjectRegionFromMember(const MemberExpr *ME, CheckerContext &C);
  static const FieldRegion* buildFieldRegionFor(const FieldDecl *FD, const MemRegion *Base, CheckerContext &C);
  static bool fieldWasSetNonZero(const FieldRegion *FR, ProgramStateRef State);

  void reportMemopBeforeCountInit(const CallEvent &Call, CheckerContext &C) const;
};

//===----------------------------------------------------------------------===//
// Helper implementations
//===----------------------------------------------------------------------===//

bool SAGenTestChecker::isZeroingAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;

  // Match common zero-initializing allocators in the kernel
  return ExprHasName(E, "kzalloc", C) ||
         ExprHasName(E, "kzalloc_node", C) ||
         ExprHasName(E, "kcalloc", C) ||
         ExprHasName(E, "kvcalloc", C) ||
         ExprHasName(E, "kvzalloc", C) ||
         ExprHasName(E, "vzalloc", C) ||
         ExprHasName(E, "devm_kzalloc", C);
}

bool SAGenTestChecker::isMemOpCall(const CallEvent &Call, unsigned &DstParamIndex, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;

  // Destination parameter index is 0 for memcpy/memmove/memset and their builtins
  if (ExprHasName(E, "memcpy", C) || ExprHasName(E, "__builtin_memcpy", C) ||
      ExprHasName(E, "memmove", C) || ExprHasName(E, "__builtin_memmove", C) ||
      ExprHasName(E, "memset", C) || ExprHasName(E, "__builtin_memset", C)) {
    DstParamIndex = 0;
    return true;
  }
  return false;
}

const MemberExpr* SAGenTestChecker::getMemberExprFromArg(const Expr *Arg, CheckerContext &C) {
  if (!Arg) return nullptr;

  // Try direct MemberExpr first
  if (const auto *ME = dyn_cast<MemberExpr>(Arg->IgnoreParenImpCasts()))
    return ME;

  // Try to find a nested MemberExpr (covers &obj->flex[0], (void*)obj->flex, etc.)
  return findSpecificTypeInChildren<MemberExpr>(Arg);
}

bool SAGenTestChecker::isFlexibleArrayField(const FieldDecl *FD) {
  if (!FD) return false;
  QualType QT = FD->getType();
  const Type *Ty = QT.getTypePtrOrNull();
  if (!Ty) return false;

  if (isa<IncompleteArrayType>(Ty))
    return true;

  if (const auto *CAT = dyn_cast<ConstantArrayType>(Ty))
    return CAT->getSize().isZero();

  return false;
}

const FieldDecl* SAGenTestChecker::getCountedByField(const FieldDecl *FlexibleArrayFD) {
  if (!FlexibleArrayFD) return nullptr;

  // Look for __counted_by attribute on the flexible array field
  if (const auto *A = FlexibleArrayFD->getAttr<CountedByAttr>()) {
    // The attribute argument is an expression that should refer to a field.
    if (const Expr *E = A->getCountExpr()) {
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
        if (const auto *FD = dyn_cast<FieldDecl>(DRE->getDecl()))
          return FD;
      }
    }
  }
  return nullptr;
}

const MemRegion* SAGenTestChecker::getBaseObjectRegionFromMember(const MemberExpr *ME, CheckerContext &C) {
  if (!ME) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(ME, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const FieldRegion* SAGenTestChecker::buildFieldRegionFor(const FieldDecl *FD, const MemRegion *Base, CheckerContext &C) {
  if (!FD || !Base) return nullptr;
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  // Base is expected to be a SubRegion (e.g., SymbolicRegion) for a heap object
  if (const auto *SR = dyn_cast<SubRegion>(Base))
    return MRMgr.getFieldRegion(FD, SR);
  return nullptr;
}

bool SAGenTestChecker::fieldWasSetNonZero(const FieldRegion *FR, ProgramStateRef State) {
  if (!FR) return false;
  const bool *V = State->get<CountFieldInitMap>(FR);
  return V && *V;
}

void SAGenTestChecker::reportMemopBeforeCountInit(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "memcpy to counted flexible array before setting its count field", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

//===----------------------------------------------------------------------===//
// Core logic
//===----------------------------------------------------------------------===//

bool SAGenTestChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  // Model zero-initializing allocators: conjure a heap region and mark it as zero-initialized.
  if (!isZeroingAllocator(Call, C))
    return false;

  const Expr *E = Call.getOriginExpr();
  if (!E) return false;

  const auto *CE = dyn_cast<CallExpr>(E);
  if (!CE) return false;

  unsigned Count = C.blockCount();
  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getPredecessor()->getLocationContext();

  DefinedSVal RetVal =
      SVB.getConjuredHeapSymbolVal(CE, LCtx, Count).castAs<DefinedSVal>();

  ProgramStateRef State = C.getState();
  // Bind return value to the call expression
  State = State->BindExpr(CE, C.getLocationContext(), RetVal);

  // Track the allocated object as zero-initialized
  if (const MemRegion *R = RetVal.getAsRegion()) {
    R = R->getBaseRegion();
    State = State->add<ZeroInitObjs>(R);
  }

  if (State)
    C.addTransition(State);
  return C.isDifferent();
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R) return;

  // We only care about stores to a field (potentially the counted_by field)
  const auto *FR = dyn_cast<FieldRegion>(R);
  if (!FR) return;

  // Only proceed if the base object is a known zero-initialized allocation
  const MemRegion *Base = FR->getSuperRegion();
  if (!Base) return;
  Base = Base->getBaseRegion();

  ProgramStateRef State = C.getState();
  if (!State->contains<ZeroInitObjs>(Base))
    return;

  // Consider the field initialized if the value is non-zero or unknown
  bool MarkInitialized = true;
  if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
    MarkInitialized = !CI->getValue().isZero();
  }

  if (MarkInitialized) {
    State = State->set<CountFieldInitMap>(FR, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned DstIdx = 0;
  if (!isMemOpCall(Call, DstIdx, C))
    return;

  if (DstIdx >= Call.getNumArgs())
    return;

  const Expr *DstE = Call.getArgExpr(DstIdx);
  if (!DstE)
    return;

  const MemberExpr *ME = getMemberExprFromArg(DstE, C);
  if (!ME)
    return;

  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return;

  // Only care about flexible arrays
  if (!isFlexibleArrayField(FD))
    return;

  // Must be annotated with __counted_by
  const FieldDecl *CountFD = getCountedByField(FD);
  if (!CountFD)
    return;

  // Find the base object region for this member access
  const MemRegion *BaseObj = getBaseObjectRegionFromMember(ME, C);
  if (!BaseObj)
    return;

  BaseObj = BaseObj->getBaseRegion();

  ProgramStateRef State = C.getState();
  // Only warn for objects known to be zero-initialized on allocation
  if (!State->contains<ZeroInitObjs>(BaseObj))
    return;

  // Build the FieldRegion for the counted_by field within this same object
  const FieldRegion *CountFR = buildFieldRegionFor(CountFD, BaseObj, C);
  if (!CountFR)
    return;

  // If we have not seen a non-zero (or unknown) write to the count field, report
  if (!fieldWasSetNonZero(CountFR, State)) {
    reportMemopBeforeCountInit(Call, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect writes to __counted_by flexible array before initializing its count field",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
