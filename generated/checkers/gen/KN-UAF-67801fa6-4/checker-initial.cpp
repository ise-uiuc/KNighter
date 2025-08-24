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
#include "clang/AST/ASTContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: published object regions and those modified after publishing.
REGISTER_SET_WITH_PROGRAMSTATE(PublishedSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(ModifiedAfterPublishSet, const MemRegion*)
// Map a published region to the call site where it was published (for diagnostics).
REGISTER_MAP_WITH_PROGRAMSTATE(PublishCallSiteMap, const MemRegion*, const Stmt*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind,
        check::PreStmt<ReturnStmt>
     > {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Publishing object before final initialization",
                       "Concurrency")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helper: identify known "publish to ID registry" calls and provide entry arg index.
  bool isPublishCall(const CallEvent &Call, CheckerContext &C,
                     unsigned &EntryIndex) const;

  // Helper: get pointee base region from a call argument by index.
  const MemRegion *getArgPointeeBaseRegion(const CallEvent &Call, unsigned Idx) const;

  // Helper: from a location SVal get the root/base region of the object being written.
  const MemRegion *getRootBaseFromLoc(SVal Loc) const;

  // Mark region as modified after publish.
  ProgramStateRef markModifiedAfterPublish(ProgramStateRef State,
                                           const MemRegion *BaseR) const;

  // Report bug for a region.
  void reportForRegion(const MemRegion *R, const Stmt *PublishSite,
                       CheckerContext &C) const;
};

bool SAGenTestChecker::isPublishCall(const CallEvent &Call, CheckerContext &C,
                                     unsigned &EntryIndex) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  // Known registry publish APIs and their entry/object parameter index.
  // - xa_alloc(xa, idp, entry, limit, gfp)
  if (ExprHasName(E, "xa_alloc", C)) {
    EntryIndex = 2;
    return true;
  }
  // - xa_store(xa, index, entry, gfp) (optional)
  if (ExprHasName(E, "xa_store", C)) {
    EntryIndex = 2;
    return true;
  }
  // - idr_alloc(idr, entry, start, end, gfp)
  if (ExprHasName(E, "idr_alloc", C)) {
    EntryIndex = 1;
    return true;
  }
  // - idr_alloc_u32(idr, entry, idp, gfp)
  if (ExprHasName(E, "idr_alloc_u32", C)) {
    EntryIndex = 1;
    return true;
  }
  // - idr_alloc_cyclic(idr, entry, start, end, gfp)
  if (ExprHasName(E, "idr_alloc_cyclic", C)) {
    EntryIndex = 1;
    return true;
  }

  return false;
}

const MemRegion *SAGenTestChecker::getArgPointeeBaseRegion(const CallEvent &Call,
                                                           unsigned Idx) const {
  if (Idx >= Call.getNumArgs())
    return nullptr;
  SVal ArgV = Call.getArgSVal(Idx);
  const MemRegion *R = ArgV.getAsRegion();
  if (!R)
    return nullptr;
  return R->getBaseRegion();
}

const MemRegion *SAGenTestChecker::getRootBaseFromLoc(SVal Loc) const {
  if (const MemRegion *R = Loc.getAsRegion())
    return R->getBaseRegion();
  return nullptr;
}

ProgramStateRef
SAGenTestChecker::markModifiedAfterPublish(ProgramStateRef State,
                                           const MemRegion *BaseR) const {
  if (!BaseR)
    return State;
  if (State->contains<PublishedSet>(BaseR)) {
    State = State->add<ModifiedAfterPublishSet>(BaseR);
  }
  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  unsigned EntryIndex = 0;
  if (!isPublishCall(Call, C, EntryIndex))
    return;

  const MemRegion *EntryBase = getArgPointeeBaseRegion(Call, EntryIndex);
  if (!EntryBase)
    return;

  // Mark as published and remember call site for diagnostics.
  State = State->add<PublishedSet>(EntryBase);
  if (const Stmt *S = Call.getOriginExpr()) {
    State = State->set<PublishCallSiteMap>(EntryBase, S);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Don't consider publish calls themselves as "modifications after publish".
  unsigned DummyIdx = 0;
  if (isPublishCall(Call, C, DummyIdx))
    return;

  // If a known-dereferencing function is called with a published object,
  // consider that as "used/modified after publish".
  llvm::SmallVector<unsigned, 4> DerefParams;
  bool HasKnownDeref = functionKnownToDeref(Call, DerefParams);

  if (HasKnownDeref) {
    for (unsigned PI : DerefParams) {
      const MemRegion *ArgBase = getArgPointeeBaseRegion(Call, PI);
      if (!ArgBase)
        continue;
      if (State->contains<PublishedSet>(ArgBase)) {
        State = State->add<ModifiedAfterPublishSet>(ArgBase);
      }
    }
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Any write into a field/element of a published object after it was published.
  const MemRegion *BaseR = getRootBaseFromLoc(Loc);
  if (!BaseR)
    return;

  if (State->contains<PublishedSet>(BaseR)) {
    State = State->add<ModifiedAfterPublishSet>(BaseR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportForRegion(const MemRegion *R, const Stmt *PublishSite,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Object inserted into ID registry before final initialization; "
           "make xa_alloc/idr_alloc the last step.",
      N);

  if (PublishSite) {
    Rpt->addRange(PublishSite->getSourceRange());
  }
  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;

  const Expr *Ret = RS->getRetValue();
  if (!Ret)
    return;

  llvm::APSInt RetVal;
  if (!EvaluateExprToInt(RetVal, Ret, C))
    return;

  // Only warn on success return (commonly 0).
  if (RetVal != 0)
    return;

  ProgramStateRef State = C.getState();
  auto ModifiedSet = State->get<ModifiedAfterPublishSet>();
  if (ModifiedSet.isEmpty())
    return;

  for (auto It = ModifiedSet.begin(); It != ModifiedSet.end(); ++It) {
    const MemRegion *R = *It;
    if (!R)
      continue;

    if (State->contains<PublishedSet>(R)) {
      const Stmt *PubSite = nullptr;
      if (const Stmt *const *P = State->get<PublishCallSiteMap>(R))
        PubSite = *P;

      reportForRegion(R, PubSite, C);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing objects into ID registries (xa/idr) before final initialization",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
