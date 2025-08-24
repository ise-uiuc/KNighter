```cpp
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
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks a pending initialization's destination region and its owning frame.
struct PendingInit {
  const MemRegion *ReqMR = nullptr;
  const StackFrameContext *Owner = nullptr;

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(ReqMR);
    ID.AddPointer(Owner);
  }

  bool operator==(const PendingInit &Other) const {
    return ReqMR == Other.ReqMR && Owner == Other.Owner;
  }
};

// Map: return-symbol of hwrm_req_init() -> {req MemRegion*, owner frame}
REGISTER_MAP_WITH_PROGRAMSTATE(PendingInitMap, SymbolRef, PendingInit)

// Map: req MemRegion* -> owner frame
REGISTER_MAP_WITH_PROGRAMSTATE(ReqOwnerMap, const MemRegion *, const StackFrameContext *)

// Map: owner frame -> number of outstanding reqs in this frame
REGISTER_MAP_WITH_PROGRAMSTATE(FrameReqCountMap, const StackFrameContext *, unsigned)

// Set: frames we have already reported on (to avoid duplicate reports on return + end)
REGISTER_SET_WITH_PROGRAMSTATE(ReportedFrames, const StackFrameContext *)

namespace {

static bool calleeIs(const CallEvent &Call, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName().equals(Name);
  return false;
}

static const StackFrameContext *getCurrentFrame(CheckerContext &C) {
  return C.getStackFrame();
}

static bool isAncestorOrSame(const StackFrameContext *MaybeAncestor,
                             const LocationContext *LC) {
  if (!MaybeAncestor || !LC)
    return false;
  const LocationContext *Cur = LC;
  while (Cur) {
    if (Cur == MaybeAncestor)
      return true;
    Cur = Cur->getParent();
  }
  return false;
}

static unsigned getFrameCount(ProgramStateRef State,
                              const StackFrameContext *F) {
  if (!F) return 0;
  if (const unsigned *Cnt = State->get<FrameReqCountMap>(F))
    return *Cnt;
  return 0;
}

static ProgramStateRef incFrameCount(ProgramStateRef State,
                                     const StackFrameContext *F) {
  if (!State || !F) return State;
  unsigned Cnt = getFrameCount(State, F);
  return State->set<FrameReqCountMap>(F, Cnt + 1);
}

static ProgramStateRef decFrameCount(ProgramStateRef State,
                                     const StackFrameContext *F) {
  if (!State || !F) return State;
  unsigned Cnt = getFrameCount(State, F);
  if (Cnt <= 1)
    return State->remove<FrameReqCountMap>(F);
  return State->set<FrameReqCountMap>(F, Cnt - 1);
}

static bool isFalsePositiveSite(const Stmt *S, CheckerContext &C) {
  if (!S) return false;
  const SourceManager &SM = C.getSourceManager();
  // Avoid attributing diagnostics to system headers (common inline helpers).
  if (SM.isInSystemHeader(S->getBeginLoc()))
    return true;
  return false;
}

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreStmt<ReturnStmt>,
    check::EndFunction,
    eval::Assume> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() {
    BT = std::make_unique<BugType>(
        this,
        "Missing hwrm_req_drop() after hwrm_req_init()",
        "Resource management");
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

private:
  void reportLeakForCurrentFrame(CheckerContext &C, const Stmt *S) const;
  void cleanupForFrame(ProgramStateRef &State, const StackFrameContext *F) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (calleeIs(Call, "hwrm_req_init")) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    if (!ReqExpr)
      return;

    const MemRegion *ReqMR = getMemRegionFromExpr(ReqExpr, C);
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;

    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (!RetSym)
      return;

    PendingInit PI;
    PI.ReqMR = ReqMR;
    PI.Owner = getCurrentFrame(C);

    State = State->set<PendingInitMap>(RetSym, PI);
    C.addTransition(State);
    return;
  }

  // Track hwrm_req_drop(bp, req)
  if (calleeIs(Call, "hwrm_req_drop")) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    if (!ReqExpr)
      return;

    const MemRegion *ReqMR = getMemRegionFromExpr(ReqExpr, C);
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;

    // Check if this req has an owner, and if the current frame is the owner
    // or a descendant of the owner. Only then consider it a valid drop.
    if (const StackFrameContext *const *OwnerPtr =
            State->get<ReqOwnerMap>(ReqMR)) {
      const StackFrameContext *Owner = *OwnerPtr;
      if (isAncestorOrSame(Owner, C.getLocationContext())) {
        State = State->remove<ReqOwnerMap>(ReqMR);
        State = decFrameCount(State, Owner);
        C.addTransition(State);
      }
    }
    return;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  // Unify symbol extraction.
  SymbolRef SE = Cond.getAsSymbol();
  if (!SE)
    return State;

  // Case A: comparison rc == 0 or rc != 0
  if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
    BinaryOperator::Opcode Op = SIE->getOpcode();
    SymbolRef Sym = SIE->getLHS();
    if (!Sym)
      return State;

    if (const PendingInit *PI = State->get<PendingInitMap>(Sym)) {
      bool SuccessBranch = false;
      if (SIE->getRHS().isZero()) {
        if (Op == BO_EQ && Assumption)
          SuccessBranch = true;     // (rc == 0) assumed true
        else if (Op == BO_NE && !Assumption)
          SuccessBranch = true;     // (rc != 0) assumed false
      }

      if (SuccessBranch) {
        // Finalize acquisition: map req -> owner and bump owner's count.
        State = State->set<ReqOwnerMap>(PI->ReqMR, PI->Owner);
        State = incFrameCount(State, PI->Owner);
      }
      // Consume the pending mapping regardless of branch.
      State = State->remove<PendingInitMap>(Sym);
      return State;
    }
    return State;
  }

  // Case B: plain symbolic 'if (rc)' form.
  if (const PendingInit *PI = State->get<PendingInitMap>(SE)) {
    // if (rc) -> Assumption true: rc != 0 (failure)
    // if (rc) -> Assumption false: rc == 0 (success)
    if (!Assumption) {
      State = State->set<ReqOwnerMap>(PI->ReqMR, PI->Owner);
      State = incFrameCount(State, PI->Owner);
    }
    State = State->remove<PendingInitMap>(SE);
    return State;
  }

  return State;
}

void SAGenTestChecker::reportLeakForCurrentFrame(CheckerContext &C, const Stmt *S) const {
  const StackFrameContext *CurF = getCurrentFrame(C);
  if (!CurF)
    return;

  ProgramStateRef State = C.getState();
  unsigned Count = getFrameCount(State, CurF);
  if (Count == 0)
    return;

  // Avoid duplicate reports for the same frame.
  if (State->contains<ReportedFrames>(CurF))
    return;

  if (isFalsePositiveSite(S, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing hwrm_req_drop() after successful hwrm_req_init()", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));

  // Mark frame as reported to avoid double-diagnostics at EndFunction.
  ProgramStateRef NewState = State->add<ReportedFrames>(CurF);
  C.addTransition(NewState);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  // Only report for returns that exit the same frame that owns outstanding reqs.
  reportLeakForCurrentFrame(C, RS);
}

void SAGenTestChecker::cleanupForFrame(ProgramStateRef &State, const StackFrameContext *F) const {
  if (!State || !F)
    return;

  // Remove all owner mappings for this frame (garbage-collect).
  llvm::SmallVector<const MemRegion *, 4> ToRemove;
  auto Map = State->get<ReqOwnerMap>();
  for (auto It = Map.begin(); It != Map.end(); ++It) {
    const MemRegion *ReqMR = It->first;
    const StackFrameContext *Owner = It->second;
    if (Owner == F)
      ToRemove.push_back(ReqMR);
  }
  for (const MemRegion *MR : ToRemove)
    State = State->remove<ReqOwnerMap>(MR);

  // Remove any pending-inits originating from this frame (not yet decided).
  llvm::SmallVector<SymbolRef, 4> PendingToErase;
  auto PMap = State->get<PendingInitMap>();
  for (auto It = PMap.begin(); It != PMap.end(); ++It) {
    SymbolRef Sym = It->first;
    const PendingInit &PI = It->second;
    if (PI.Owner == F)
      PendingToErase.push_back(Sym);
  }
  for (SymbolRef Sym : PendingToErase)
    State = State->remove<PendingInitMap>(Sym);

  // Finally clear the frame's count and its reported flag.
  State = State->remove<FrameReqCountMap>(F);
  State = State->remove<ReportedFrames>(F);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Report if we exit a function that still has outstanding reqs for this frame.
  // We intentionally do not attribute it to a specific source range here.
  reportLeakForCurrentFrame(C, nullptr);

  // Clean up all per-frame state to avoid stale data leaking into callers.
  ProgramStateRef State = C.getState();
  cleanupForFrame(State, getCurrentFrame(C));
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing hwrm_req_drop() after successful hwrm_req_init() within the same function",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
