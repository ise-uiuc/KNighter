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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Type.h"
#include "llvm/Support/Casting.h"
#include "llvm/Config/llvm-config.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Track zero-initialized heap objects (e.g., kzalloc/kcalloc/devm_kzalloc/kvzalloc)
REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitAllocs, const MemRegion*)
// Track count fields (as FieldRegion) that have been initialized (assigned)
REGISTER_SET_WITH_PROGRAMSTATE(InitializedCountFields, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::Bind
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Write to __counted_by array before count init", "Memory Error")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      bool isZeroInitAllocator(const CallEvent &Call, CheckerContext &C) const;
      bool isMemWriteLike(const CallEvent &Call, CheckerContext &C) const;

      // Retrieve the controlling FieldDecl from a __counted_by attribute on an array field.
      const FieldDecl *getCountedByField(const FieldDecl *ArrayFD) const;

      // Walk up the MemRegion chain to find the FieldRegion that represents the destination array.
      const FieldRegion *findArrayFieldRegionFromDest(const MemRegion *DestRegion) const;

      // Build a FieldRegion for FD on a given base object region.
      const FieldRegion *makeFieldRegionFor(const MemRegion *BaseObj,
                                            const FieldDecl *FD,
                                            CheckerContext &C) const;

      void reportEarlyWriteToCountedByArray(const CallEvent &Call,
                                            const Expr *DstExpr,
                                            CheckerContext &C) const;
};

// Determine if the call is a zero-initializing allocator
bool SAGenTestChecker::isZeroInitAllocator(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // Common zero-initializing allocators in the kernel
  if (ExprHasName(OE, "kzalloc", C)) return true;
  if (ExprHasName(OE, "kcalloc", C)) return true;
  if (ExprHasName(OE, "kvzalloc", C)) return true;
  if (ExprHasName(OE, "devm_kzalloc", C)) return true;
  if (ExprHasName(OE, "devm_kcalloc", C)) return true;

  return false;
}

// Determine if the call is a memory write/copy like memcpy/memmove
bool SAGenTestChecker::isMemWriteLike(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // Minimal set to catch the pattern
  if (ExprHasName(OE, "memcpy", C)) return true;
  if (ExprHasName(OE, "__builtin_memcpy", C)) return true;
  if (ExprHasName(OE, "memmove", C)) return true;
  if (ExprHasName(OE, "__builtin_memmove", C)) return true;

  return false;
}

// Return the controlling count field for a __counted_by flexible array, if any.
const FieldDecl *SAGenTestChecker::getCountedByField(const FieldDecl *ArrayFD) const {
  if (!ArrayFD) return nullptr;

  // Check the array is flexible (incomplete) to avoid false positives
  QualType QT = ArrayFD->getType();
  if (!isa<IncompleteArrayType>(QT.getTypePtr())) {
    return nullptr;
  }

  // Require __counted_by attribute
  if (!ArrayFD->hasAttr<CountedByAttr>())
    return nullptr;

  const auto *CBA = ArrayFD->getAttr<CountedByAttr>();
  if (!CBA)
    return nullptr;

  const FieldDecl *CountFD = nullptr;
#if LLVM_VERSION_MAJOR >= 19
  const Expr *E = CBA->getCountedBy();
  if (E) {
    E = E->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      CountFD = dyn_cast<FieldDecl>(DRE->getDecl());
    } else if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      CountFD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    }
  }
#else
  // In Clang 18, CountedByAttr exposes the resolved FieldDecl directly.
  CountFD = CBA->getCountedByField();
#endif

  return CountFD;
}

// Ascend region chain to find the FieldRegion representing the array field
const FieldRegion *SAGenTestChecker::findArrayFieldRegionFromDest(const MemRegion *DestRegion) const {
  const MemRegion *R = DestRegion;
  while (R) {
    if (const auto *FR = dyn_cast<FieldRegion>(R))
      return FR;
    if (const auto *SR = dyn_cast<SubRegion>(R))
      R = SR->getSuperRegion();
    else
      break;
  }
  return nullptr;
}

// Construct the FieldRegion for FD on the given base object region
const FieldRegion *SAGenTestChecker::makeFieldRegionFor(const MemRegion *BaseObj,
                                                        const FieldDecl *FD,
                                                        CheckerContext &C) const {
  if (!BaseObj || !FD) return nullptr;
  const auto *TVR = dyn_cast<TypedValueRegion>(BaseObj);
  if (!TVR) return nullptr;
  MemRegionManager &RM = C.getSValBuilder().getRegionManager();
  return RM.getFieldRegion(FD, TVR);
}

// Post-call: mark zero-initialized allocations' regions
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroInitAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();

  // Get the region of the returned pointer
  const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
  if (!RetReg)
    return;

  // Use base region for stable identity
  RetReg = RetReg->getBaseRegion();
  if (!RetReg)
    return;

  State = State->add<ZeroInitAllocs>(RetReg);
  C.addTransition(State);
}

// Bind: when a field is assigned, mark that field as initialized.
// We don't filter here; we store FieldRegion in the set, and only query it
// for counted_by controlling fields later.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  if (const auto *FR = dyn_cast<FieldRegion>(R)) {
    ProgramStateRef State = C.getState();
    // Insert the exact FieldRegion; do not strip base region here.
    State = State->add<InitializedCountFields>(FR);
    C.addTransition(State);
  }
}

// Report helper
void SAGenTestChecker::reportEarlyWriteToCountedByArray(const CallEvent &Call,
                                                        const Expr *DstExpr,
                                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Write to __counted_by array before initializing its count", N);
  if (DstExpr)
    R->addRange(DstExpr->getSourceRange());
  else
    R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

// Pre-call: detect memcpy/memmove to a __counted_by array before the count is set
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isMemWriteLike(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  // Destination pointer
  const Expr *DstExpr = Call.getArgExpr(0);
  SVal DstVal = Call.getArgSVal(0);
  const MemRegion *DstReg = DstVal.getAsRegion();
  if (!DstReg)
    return;

  // Find the array field region from the destination region
  const FieldRegion *ArrayFR = findArrayFieldRegionFromDest(DstReg);
  if (!ArrayFR)
    return;

  const FieldDecl *ArrayFD = ArrayFR->getDecl();
  if (!ArrayFD)
    return;

  // Check it's a flexible array member with __counted_by
  const FieldDecl *CountFD = getCountedByField(ArrayFD);
  if (!CountFD)
    return;

  // Get the base object region that owns this field/array
  const MemRegion *BaseObj = ArrayFR->getSuperRegion();
  if (!BaseObj)
    return;
  BaseObj = BaseObj->getBaseRegion();
  if (!BaseObj)
    return;

  // Only warn if this object is known zero-initialized (e.g., kzalloc)
  ProgramStateRef State = C.getState();
  if (!State->contains<ZeroInitAllocs>(BaseObj))
    return;

  // Now reconstruct the FieldRegion for the controlling count field on this base object
  const FieldRegion *CountFR = makeFieldRegionFor(BaseObj, CountFD, C);
  if (!CountFR)
    return;

  // If the controlling field wasn't initialized yet, this is a bug
  if (!State->contains<InitializedCountFields>(CountFR)) {
    reportEarlyWriteToCountedByArray(Call, DstExpr, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect writes to __counted_by flexible array before initializing the controlling count (on zero-initialized objects)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
