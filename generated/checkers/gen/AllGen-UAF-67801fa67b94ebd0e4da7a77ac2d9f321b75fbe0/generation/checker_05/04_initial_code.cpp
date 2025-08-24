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
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: published object region -> publish site stmt
REGISTER_MAP_WITH_PROGRAMSTATE(PublishedRegionMap, const MemRegion*, const Stmt*)
// Program state: pointer aliasing
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
// Program state: already reported regions
REGISTER_SET_WITH_PROGRAMSTATE(ReportedSet, const MemRegion*)

namespace {
class SAGenTestChecker : public Checker<
  check::PostCall,
  check::PreCall,
  check::Bind
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Early publication to ID/XArray", "Memory Safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:
      // Helpers
      const MemRegion *getRootAlias(const MemRegion *R, ProgramStateRef State) const;
      bool isIdPublishCall(const CallEvent &Call, CheckerContext &C, unsigned &EntryArgIndex) const;
      void reportPublishedThenUsed(const MemRegion *PubR, const Stmt *UseSite,
                                   const Stmt *PublishSite, CheckerContext &C) const;
};
} // end anonymous namespace

// Resolve alias chain to a canonical base region.
const MemRegion *SAGenTestChecker::getRootAlias(const MemRegion *R, ProgramStateRef State) const {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break;
    const MemRegion *Next = State->get<PtrAliasMap>(Cur);
    if (!Next)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur;
}

// Identify calls that publish an object to ID/XArray and return which argument holds the entry pointer.
bool SAGenTestChecker::isIdPublishCall(const CallEvent &Call, CheckerContext &C, unsigned &EntryArgIndex) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // XArray interfaces
  if (ExprHasName(OE, "xa_alloc", C) || ExprHasName(OE, "xa_alloc_cyclic", C)) {
    if (Call.getNumArgs() > 2) {
      EntryArgIndex = 2; // (xa, id, entry, ...)
      return true;
    }
  }
  if (ExprHasName(OE, "xa_store", C)) {
    if (Call.getNumArgs() > 2) {
      EntryArgIndex = 2; // (xa, index, entry, ...)
      return true;
    }
  }

  // IDR interfaces
  if (ExprHasName(OE, "idr_alloc_u32", C) ||
      ExprHasName(OE, "idr_alloc_cyclic", C) ||
      ExprHasName(OE, "idr_alloc", C) ||
      ExprHasName(OE, "idr_replace", C)) {
    if (Call.getNumArgs() > 1) {
      EntryArgIndex = 1; // (idr, ptr, ...)
      return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportPublishedThenUsed(const MemRegion *PubR, const Stmt *UseSite,
                                               const Stmt *PublishSite, CheckerContext &C) const {
  if (!PubR)
    return;
  ProgramStateRef State = C.getState();
  if (State->contains<ReportedSet>(PubR))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Object published to ID/XArray before fully initialized; later access detected (potential UAF).", N);

  if (UseSite)
    Rpt->addRange(UseSite->getSourceRange());
  if (PublishSite)
    Rpt->addRange(PublishSite->getSourceRange());

  C.emitReport(std::move(Rpt));

  State = State->add<ReportedSet>(PubR);
  C.addTransition(State);
}

// Publish detection and also post-call usage detection for non-publish calls (best-effort via deref-known table).
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // First, detect publish calls and record the published pointer region.
  unsigned EntryIdx = 0;
  if (isIdPublishCall(Call, C, EntryIdx)) {
    if (EntryIdx < Call.getNumArgs()) {
      const Expr *EntryE = Call.getArgExpr(EntryIdx);
      if (EntryE) {
        const MemRegion *ER = getMemRegionFromExpr(EntryE, C);
        if (ER) {
          ER = ER->getBaseRegion();
          const MemRegion *Root = getRootAlias(ER, State);
          if (Root) {
            const Stmt *PublishSite = Call.getOriginExpr();
            State = State->set<PublishedRegionMap>(Root, PublishSite ? PublishSite : (const Stmt*)EntryE);
            C.addTransition(State);
          }
        }
      }
    }
    return;
  }

  // Optional: after publication, if we call a function that is known to dereference a published pointer argument,
  // report it as "use after publication" in the creation path.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;
    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *AR = getMemRegionFromExpr(ArgE, C);
    if (!AR)
      continue;
    AR = AR->getBaseRegion();
    const MemRegion *Root = getRootAlias(AR, State);
    if (!Root)
      continue;

    const Stmt *PubSite = State->get<PublishedRegionMap>(Root);
    if (!PubSite)
      continue;

    if (!State->contains<ReportedSet>(Root)) {
      reportPublishedThenUsed(Root, Call.getOriginExpr(), PubSite, C);
      return;
    }
  }
}

// Pre-call: also catch dereferences by known-deref functions before the call executes.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  unsigned DummyIdx = 0;
  if (isIdPublishCall(Call, C, DummyIdx))
    return; // don't process publish here

  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *AR = getMemRegionFromExpr(ArgE, C);
    if (!AR)
      continue;

    AR = AR->getBaseRegion();
    const MemRegion *Root = getRootAlias(AR, State);
    if (!Root)
      continue;

    const Stmt *PubSite = State->get<PublishedRegionMap>(Root);
    if (!PubSite)
      continue;

    if (!State->contains<ReportedSet>(Root)) {
      reportPublishedThenUsed(Root, Call.getOriginExpr(), PubSite, C);
      return;
    }
  }
}

// Bind: track aliasing (pointer assignments) and detect member stores to a published object.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track pointer aliasing on simple assignments: p2 = p1;
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(StoreE)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      if (LHS && RHS && LHS->getType()->isPointerType() && RHS->getType()->isPointerType()) {
        const MemRegion *LHSR = getMemRegionFromExpr(LHS, C);
        const MemRegion *RHSR = getMemRegionFromExpr(RHS, C);
        if (LHSR && RHSR) {
          LHSR = LHSR->getBaseRegion();
          RHSR = RHSR->getBaseRegion();
          const MemRegion *RootL = getRootAlias(LHSR, State);
          const MemRegion *RootR = getRootAlias(RHSR, State);
          if (RootL && RootR) {
            State = State->set<PtrAliasMap>(RootL, RootR);
            State = State->set<PtrAliasMap>(RootR, RootL);
            C.addTransition(State);
          }
        }
      }
    }
  }

  // Detect member store to a published object: q->field = ...
  // Focus on assignment statements to a field/member.
  const auto *BO = dyn_cast_or_null<BinaryOperator>(StoreE);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  if (!LHS)
    return;

  // We only care about LHS that is a member expression (e.g., q->xef)
  const MemberExpr *ME = dyn_cast<MemberExpr>(LHS);
  if (!ME)
    return;

  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return;

  const MemRegion *BaseR = getMemRegionFromExpr(BaseE, C);
  if (!BaseR)
    return;

  BaseR = BaseR->getBaseRegion();
  const MemRegion *Root = getRootAlias(BaseR, State);
  if (!Root)
    return;

  const Stmt *PubSite = State->get<PublishedRegionMap>(Root);
  if (!PubSite)
    return;

  if (State->contains<ReportedSet>(Root))
    return;

  // Report: writing to the object after it has been published.
  reportPublishedThenUsed(Root, StoreE, PubSite, C);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects early publication to ID/XArray (xa_alloc/idr_alloc/xa_store) before full initialization, causing potential UAF",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
