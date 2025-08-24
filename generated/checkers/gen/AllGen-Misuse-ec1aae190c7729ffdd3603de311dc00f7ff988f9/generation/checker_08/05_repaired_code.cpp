#include <memory>
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

REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitBases, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(InitCountFields, const MemRegion*)

namespace {

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Flexible array accessed before __counted_by init", "Memory Safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool isZeroingAllocator(const CallEvent &Call, CheckerContext &C);
      static bool isMemWriteCallAndDstIndex(const CallEvent &Call, CheckerContext &C, unsigned &DstIndex);
      static const MemRegion *getRootBase(const MemRegion *R);
      static const FieldRegion *findEnclosingFieldRegion(const MemRegion *R);
      static const FieldDecl *getCountedByFieldViaAttr(const FieldDecl *F);
      static const FieldDecl *getCountedByFieldHeuristic(const FieldDecl *F, const Expr *DestE);
      void reportFlexibleArrayBeforeCountInit(const CallEvent &Call, const Expr *DestE, CheckerContext &C) const;
};

static bool hasName(const Expr *Origin, StringRef Name, CheckerContext &C) {
  if (!Origin) return false;
  return ExprHasName(Origin, Name, C);
}

bool SAGenTestChecker::isZeroingAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  // Common zero-initializing allocators in the kernel
  return hasName(E, "kzalloc", C) ||
         hasName(E, "devm_kzalloc", C) ||
         hasName(E, "kcalloc", C) ||
         hasName(E, "kzalloc_node", C) ||
         hasName(E, "kvzalloc", C);
}

bool SAGenTestChecker::isMemWriteCallAndDstIndex(const CallEvent &Call, CheckerContext &C, unsigned &DstIndex) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;

  // Functions that write to destination pointer in arg0
  if (hasName(E, "memcpy", C) || hasName(E, "memmove", C) || hasName(E, "memset", C)) {
    DstIndex = 0;
    return true;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getRootBase(const MemRegion *R) {
  if (!R) return nullptr;
  return R->getBaseRegion();
}

const FieldRegion *SAGenTestChecker::findEnclosingFieldRegion(const MemRegion *R) {
  if (!R) return nullptr;
  const MemRegion *Cur = R;
  while (Cur) {
    if (const auto *FR = dyn_cast<FieldRegion>(Cur))
      return FR;
    const auto *SR = dyn_cast<SubRegion>(Cur);
    if (!SR) break;
    Cur = SR->getSuperRegion();
  }
  return nullptr;
}

const FieldDecl *SAGenTestChecker::getCountedByFieldViaAttr(const FieldDecl *F) {
  if (!F) return nullptr;
  const auto *Attr = F->getAttr<CountedByAttr>();
  if (!Attr) return nullptr;

  // Clang 18 API: CountedByAttr::getCountedByField() returns IdentifierInfo*.
  if (IdentifierInfo *II = Attr->getCountedByField()) {
    const RecordDecl *RD = dyn_cast<RecordDecl>(F->getParent());
    if (!RD) return nullptr;
    for (const FieldDecl *FD : RD->fields()) {
      if (FD->getIdentifier() == II || FD->getName() == II->getName())
        return FD;
    }
  }

  return nullptr;
}

const FieldDecl *SAGenTestChecker::getCountedByFieldHeuristic(const FieldDecl *F, const Expr * /*DestE*/) {
  if (!F) return nullptr;

  // Only apply conservative heuristic for flexible arrays (incomplete array type).
  QualType FT = F->getType();
  if (!isa<IncompleteArrayType>(FT.getTypePtr()))
    return nullptr;

  const RecordDecl *RD = dyn_cast<RecordDecl>(F->getParent());
  if (!RD) return nullptr;

  static const char *Names[] = {"datalen", "len", "length", "size"};
  for (const FieldDecl *FD : RD->fields()) {
    StringRef N = FD->getName();
    for (auto *T : Names) {
      if (N.equals(T))
        return FD;
    }
  }
  return nullptr;
}

void SAGenTestChecker::reportFlexibleArrayBeforeCountInit(const CallEvent &Call, const Expr *DestE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Flexible array accessed before initializing its __counted_by field", N);
  if (DestE)
    R->addRange(DestE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroingAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
  if (!RetReg)
    return;

  // Track the returned base (heap/symbolic) region as zero-initialized.
  const MemRegion *Base = getRootBase(RetReg);
  if (!Base)
    return;

  State = State->add<ZeroInitBases>(Base);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *L = Loc.getAsRegion();
  if (!L)
    return;

  // Find field region being written, if any.
  const FieldRegion *FR = findEnclosingFieldRegion(L);
  if (!FR)
    return;

  // Only track initialization for objects we know are zero-initialized.
  const MemRegion *Root = getRootBase(FR);
  if (!Root)
    return;
  if (!State->contains<ZeroInitBases>(Root))
    return;

  // Record that this specific field for this object instance has been initialized at least once.
  State = State->add<InitCountFields>(FR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned DstIndex = 0;
  if (!isMemWriteCallAndDstIndex(Call, C, DstIndex))
    return;

  if (Call.getNumArgs() <= DstIndex)
    return;

  const Expr *DestE = Call.getArgExpr(DstIndex);
  if (!DestE)
    return;

  // Obtain the destination memory region.
  const MemRegion *DstRegExpr = getMemRegionFromExpr(DestE, C);
  if (!DstRegExpr)
    return;

  // Always get base region after extracting from expression (per suggestions).
  const MemRegion *DstBase = DstRegExpr->getBaseRegion();
  (void)DstBase; // We'll use it later for ZeroInitBases check via the field region.

  // We need to identify if this points into a flexible-array member (FieldRegion).
  const FieldRegion *FAMFieldReg = findEnclosingFieldRegion(DstRegExpr);
  if (!FAMFieldReg)
    return;

  const FieldDecl *FAMFD = FAMFieldReg->getDecl();
  if (!FAMFD)
    return;

  // Ensure it's a flexible array type.
  QualType FT = FAMFD->getType();
  if (!isa<IncompleteArrayType>(FT.getTypePtr()))
    return;

  // Try to obtain the counted_by field via the attribute first.
  const FieldDecl *CountFD = getCountedByFieldViaAttr(FAMFD);

  // If attribute isn't available, try conservative heuristic targeted at the given pattern.
  if (!CountFD) {
    // Only apply heuristic if the dest expression text suggests this is "->data"
    if (ExprHasName(DestE, "->data", C)) {
      CountFD = getCountedByFieldHeuristic(FAMFD, DestE);
    }
  }

  if (!CountFD)
    return; // Can't confidently relate to a counter; don't warn.

  // This should be the same object instance as the FAM field's super region.
  const MemRegion *ObjSuper = FAMFieldReg->getSuperRegion();
  if (!ObjSuper)
    return;

  // Verify the root object was zero-initialized (kzalloc-family).
  const MemRegion *Root = getRootBase(ObjSuper);
  if (!Root)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<ZeroInitBases>(Root))
    return; // We only care about the kzalloc-style pattern.

  // Construct the FieldRegion for the counted_by field on the same object.
  MemRegionManager &RM = C.getSValBuilder().getRegionManager();
  const SubRegion *ObjSub = dyn_cast<SubRegion>(ObjSuper);
  if (!ObjSub)
    return;
  const FieldRegion *CountFR = RM.getFieldRegion(CountFD, ObjSub);
  if (!CountFR)
    return;

  // If the count field hasn't been initialized yet, report.
  if (!State->contains<InitCountFields>(CountFR)) {
    reportFlexibleArrayBeforeCountInit(Call, DestE, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects flexible-array accesses before initializing their __counted_by field (after zeroing allocation)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
