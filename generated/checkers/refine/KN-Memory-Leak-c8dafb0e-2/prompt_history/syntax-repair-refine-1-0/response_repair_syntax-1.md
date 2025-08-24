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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Map: return-symbol of hwrm_req_init() -> req MemRegion*
REGISTER_MAP_WITH_PROGRAMSTATE(PendingInitMap, SymbolRef, const MemRegion *)

// Map: return-symbol of hwrm_req_init() -> the StackFrameContext* where call occurred
REGISTER_MAP_WITH_PROGRAMSTATE(PendingInitSFCMap, SymbolRef, const StackFrameContext *)

// Map: tracked req MemRegion* -> the StackFrameContext* where it became "acquired"
REGISTER_MAP_WITH_PROGRAMSTATE(AcquiredReqMap, const MemRegion *, const StackFrameContext *)

namespace {

static const StackFrameContext *getSFC(const CheckerContext &C) {
  return C.getLocationContext()->getStackFrame();
}

static bool calleeMatchesAny(const CallEvent &Call,
                             llvm::ArrayRef<StringRef> Names) {
  // Primary: IdentifierInfo from the callee
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    for (StringRef N : Names)
      if (FnName.equals(N))
        return true;
  }

  // Secondary: Decl name (handles static inline wrappers)
  if (const Decl *D = Call.getDecl()) {
    if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
      if (const IdentifierInfo *ID2 = FD->getIdentifier()) {
        StringRef FnName = ID2->getName();
        for (StringRef N : Names)
          if (FnName.equals(N))
            return true;
      } else {
        // In rare cases, fall back to qualified name
        std::string QN = FD->getQualifiedNameAsString();
        for (StringRef N : Names)
          if (StringRef(QN).endswith(N))
            return true;
      }
    }
  }

  // Last resort: attempt to match from the origin expression
  if (const Expr *Origin = Call.getOriginExpr()) {
    const Expr *E = Origin->IgnoreParenCasts();
    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      const Expr *CalleeExpr = CE->getCallee();
      if (CalleeExpr)
        CalleeExpr = CalleeExpr->IgnoreParenCasts();
      if (const auto *DRE = dyn_cast_or_null<DeclRefExpr>(CalleeExpr)) {
        if (const ValueDecl *VD = DRE->getDecl()) {
          if (const IdentifierInfo *ID3 = VD->getIdentifier()) {
            StringRef FnName = ID3->getName();
            for (StringRef N : Names)
              if (FnName.equals(N))
                return true;
          }
        }
      }
    }
  }

  return false;
}

static const MemRegion *getBaseRegionFromArgExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
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
        "Resource management",
        /*SuppressOnSink=*/true);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

private:
  void reportAndCleanupForFrame(CheckerContext &C, const Stmt *S) const;
  static ProgramStateRef addAcquired(ProgramStateRef State,
                                     const MemRegion *ReqMR,
                                     const StackFrameContext *SFC);
  static ProgramStateRef removeAcquiredByReq(ProgramStateRef State,
                                             const MemRegion *ReqMR);
  static bool hasAcquiredInFrame(ProgramStateRef State,
                                 const StackFrameContext *SFC);
  static ProgramStateRef clearFrameAcquired(ProgramStateRef State,
                                            const StackFrameContext *SFC);
};

ProgramStateRef SAGenTestChecker::addAcquired(ProgramStateRef State,
                                              const MemRegion *ReqMR,
                                              const StackFrameContext *SFC) {
  if (!ReqMR || !SFC)
    return State;
  return State->set<AcquiredReqMap>(ReqMR, SFC);
}

ProgramStateRef SAGenTestChecker::removeAcquiredByReq(ProgramStateRef State,
                                                      const MemRegion *ReqMR) {
  if (!ReqMR)
    return State;
  if (State->get<AcquiredReqMap>(ReqMR))
    State = State->remove<AcquiredReqMap>(ReqMR);
  return State;
}

bool SAGenTestChecker::hasAcquiredInFrame(ProgramStateRef State,
                                          const StackFrameContext *SFC) {
  if (!SFC)
    return false;
  auto Map = State->get<AcquiredReqMap>();
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    if (I->second == SFC)
      return true;
  }
  return false;
}

ProgramStateRef SAGenTestChecker::clearFrameAcquired(ProgramStateRef State,
                                                     const StackFrameContext *SFC) {
  if (!SFC)
    return State;
  auto Map = State->get<AcquiredReqMap>();
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    if (I->second == SFC)
      State = State->remove<AcquiredReqMap>(I->first);
  }
  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (calleeMatchesAny(Call, {"hwrm_req_init", "bnxt_req_init"})) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    const MemRegion *ReqMR = getBaseRegionFromArgExpr(ReqExpr, C);
    if (!ReqMR)
      return;

    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (!RetSym)
      return;

    // Record pending init => decide success in evalAssume
    State = State->set<PendingInitMap>(RetSym, ReqMR);
    State = State->set<PendingInitSFCMap>(RetSym, getSFC(C));
    C.addTransition(State);
    return;
  }

  // Track hwrm_req_drop(bp, req)
  if (calleeMatchesAny(Call, {"hwrm_req_drop", "bnxt_req_drop"})) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    const MemRegion *ReqMR = getBaseRegionFromArgExpr(ReqExpr, C);
    if (!ReqMR)
      return;

    State = removeAcquiredByReq(State, ReqMR);
    C.addTransition(State);
    return;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  // Case 1: Direct symbolic condition: if (rc) ...
  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    if (SymbolRef Sym = NL->getAsSymbol()) {
      if (const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym)) {
        if (!Assumption) {
          const StackFrameContext *const *PendingSFC = State->get<PendingInitSFCMap>(Sym);
          if (PendingSFC && *PendingSFC)
            State = addAcquired(State, *PendingReq, *PendingSFC);
        }
        State = State->remove<PendingInitMap>(Sym);
        State = State->remove<PendingInitSFCMap>(Sym);
      }
      return State;
    }

    // Case 2: Comparison with zero: if (rc == 0) or if (rc != 0)
    if (SymbolRef SE = Cond.getAsSymbol()) {
      if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        SymbolRef Sym = SIE->getLHS();
        const llvm::APSInt &RHS = SIE->getRHS();
        if (Sym) {
          if (const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym)) {
            bool SuccessBranch = false;
            if (RHS == 0) {
              if (Op == BO_EQ && Assumption)
                SuccessBranch = true;        // (rc == 0) true
              else if (Op == BO_NE && !Assumption)
                SuccessBranch = true;        // !(rc != 0) -> rc == 0
            }
            if (SuccessBranch) {
              const StackFrameContext *const *PendingSFC = State->get<PendingInitSFCMap>(Sym);
              if (PendingSFC && *PendingSFC)
                State = addAcquired(State, *PendingReq, *PendingSFC);
            }
            State = State->remove<PendingInitMap>(Sym);
            State = State->remove<PendingInitSFCMap>(Sym);
          }
        }
      }
    }
  }

  return State;
}

void SAGenTestChecker::reportAndCleanupForFrame(CheckerContext &C, const Stmt *S) const {
  ProgramStateRef State = C.getState();
  const StackFrameContext *SFC = getSFC(C);
  if (!hasAcquiredInFrame(State, SFC))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing hwrm_req_drop() after successful hwrm_req_init()", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));

  // Clean up: remove all acquired reqs belonging to this frame to avoid
  // duplicated reports on subsequent returns or in unrelated code.
  ProgramStateRef NewState = clearFrameAcquired(State, SFC);
  C.addTransition(NewState);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  // Report only for the frame where the resource was acquired.
  reportAndCleanupForFrame(C, RS);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // In case we reach the end of the function without hitting an explicit return,
  // still report for outstanding reqs acquired in this frame.
  reportAndCleanupForFrame(C, RS);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing hwrm_req_drop() after successful hwrm_req_init()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
