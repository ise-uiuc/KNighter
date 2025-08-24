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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
// Map the pointee region of the published object -> the publish call site (for diagnostics).
REGISTER_MAP_WITH_PROGRAMSTATE(PublishSiteMap, const MemRegion*, const Stmt*)
// Map the object region -> the guard VarRegion (error/status variable). Used to gate success.
// Note: We record it, but in this implementation we publish immediately and keep the guard
// to potentially extend later.
REGISTER_MAP_WITH_PROGRAMSTATE(PendingPublishGuard, const MemRegion*, const VarRegion*)
// Reverse map from guard variable to object region.
REGISTER_MAP_WITH_PROGRAMSTATE(GuardToObject, const VarRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::Bind
  > {

   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Early publish to xa/idr", "API Misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  bool isPublishAPI(const CallEvent &Call, CheckerContext &C, unsigned &ObjParamIdx) const;
  const MemRegion *getObjRegionFromArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
  const VarRegion *getAssignedLHSVarRegion(const CallEvent &Call, CheckerContext &C) const;

  bool isPublishedFinal(ProgramStateRef State, const MemRegion *ObjBase) const;
  void reportUseAfterPublish(const MemRegion *ObjBase, const Stmt *UseSite,
                             CheckerContext &C) const;
};

bool SAGenTestChecker::isPublishAPI(const CallEvent &Call, CheckerContext &C, unsigned &ObjParamIdx) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // xa_* family, object is 3rd argument (index 2)
  if (ExprHasName(Origin, "xa_alloc", C) ||
      ExprHasName(Origin, "xa_insert", C) ||
      ExprHasName(Origin, "xa_store", C)) {
    ObjParamIdx = 2;
    return Call.getNumArgs() > ObjParamIdx;
  }

  // idr_* family, object is 2nd argument (index 1)
  if (ExprHasName(Origin, "idr_alloc", C) ||
      ExprHasName(Origin, "idr_alloc_cyclic", C) ||
      ExprHasName(Origin, "idr_replace", C)) {
    ObjParamIdx = 1;
    return Call.getNumArgs() > ObjParamIdx;
  }

  return false;
}

const MemRegion *SAGenTestChecker::getObjRegionFromArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  if (Idx >= Call.getNumArgs())
    return nullptr;

  const Expr *ArgE = Call.getArgExpr(Idx);
  if (!ArgE)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

const VarRegion *SAGenTestChecker::getAssignedLHSVarRegion(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return nullptr;

  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return nullptr;

  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(CE, C);
  if (!BO)
    return nullptr;
  if (!BO->isAssignmentOp())
    return nullptr;

  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return nullptr;

  const MemRegion *LHSRegion = getMemRegionFromExpr(LHS, C);
  if (!LHSRegion)
    return nullptr;

  LHSRegion = LHSRegion->getBaseRegion();
  return dyn_cast<VarRegion>(LHSRegion);
}

bool SAGenTestChecker::isPublishedFinal(ProgramStateRef State, const MemRegion *ObjBase) const {
  if (!ObjBase)
    return false;
  // Consider published if we have a publish site and no pending guard for the object.
  const Stmt *const *Site = State->get<PublishSiteMap>(ObjBase);
  if (!Site)
    return false;

  const VarRegion *const *Pending = State->get<PendingPublishGuard>(ObjBase);
  // If there's a recorded pending guard we could choose to delay, but for robustness and to
  // catch the target buggy pattern, we treat the presence of a publish site as sufficient.
  // If you want to enforce success-only paths, change this to (Pending == nullptr).
  (void)Pending;
  return true;
}

void SAGenTestChecker::reportUseAfterPublish(const MemRegion *ObjBase, const Stmt *UseSite,
                                             CheckerContext &C) const {
  if (!ObjBase || !UseSite)
    return;

  ProgramStateRef State = C.getState();
  const Stmt *const *PubSite = State->get<PublishSiteMap>(ObjBase);
  if (!PubSite)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Object published to xa/idr before finalization; writes/use after publish may cause UAF.", N);

  // Highlight the use site and the publish site.
  R->addRange(UseSite->getSourceRange());
  if (*PubSite)
    R->addRange((*PubSite)->getSourceRange());

  C.emitReport(std::move(R));

  // Avoid duplicate reports for the same object by clearing the publish entry.
  State = State->remove<PublishSiteMap>(ObjBase);
  State = State->remove<PendingPublishGuard>(ObjBase);
  // We don't have the VarRegion for the guard here; clear all GuardToObject that map to this object.
  // This is optional and skipped for simplicity.

  C.addTransition(State);
}

// Record potential publish site and associate guard if present.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned ObjIdx = 0;
  if (!isPublishAPI(Call, C, ObjIdx))
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *ObjBase = getObjRegionFromArg(Call, ObjIdx, C);
  if (!ObjBase)
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return;

  // Record publish site for diagnostics.
  State = State->set<PublishSiteMap>(ObjBase, CE);

  // If assigned to a guard variable (e.g., "err = xa_alloc(...)"), record it.
  if (const VarRegion *VR = getAssignedLHSVarRegion(Call, C)) {
    State = State->set<PendingPublishGuard>(ObjBase, VR);
    State = State->set<GuardToObject>(VR, ObjBase);
  }

  // In this implementation, we consider the object published right away to catch the target bug.
  // More advanced gating on success can be added by inspecting branch assumptions.

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  // Detect writes to an already published object (e.g., q->field = ...)
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const MemRegion *Base = MR->getBaseRegion();
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  if (isPublishedFinal(State, Base)) {
    reportUseAfterPublish(Base, S, C);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Skip publish APIs here; they are handled in checkPostCall.
  unsigned TmpIdx = 0;
  if (isPublishAPI(Call, C, TmpIdx))
    return;

  ProgramStateRef State = C.getState();

  // If the callee is known to dereference some params, check those.
  llvm::SmallVector<unsigned, 4> DerefParams;
  bool KnownDeref = functionKnownToDeref(Call, DerefParams);

  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE)
      continue;

    const MemRegion *ArgReg = getMemRegionFromExpr(ArgE, C);
    if (!ArgReg)
      continue;

    ArgReg = ArgReg->getBaseRegion();
    if (!ArgReg)
      continue;

    if (!isPublishedFinal(State, ArgReg))
      continue;

    // If we know this param will be dereferenced, report immediately.
    if (KnownDeref) {
      if (llvm::is_contained(DerefParams, I)) {
        reportUseAfterPublish(ArgReg, Call.getOriginExpr(), C);
        continue;
      }
    }

    // Additionally, if the argument is an address of a subfield (&q->field),
    // the base region will still match the object. Be conservative and report.
    // This catches patterns like list_add_tail(&q->list, ...).
    reportUseAfterPublish(ArgReg, Call.getOriginExpr(), C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing kernel objects to xa/idr before finalization which enables UAF via post-publish writes/uses",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
