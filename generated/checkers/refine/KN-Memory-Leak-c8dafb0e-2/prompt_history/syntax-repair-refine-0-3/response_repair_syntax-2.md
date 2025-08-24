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

// Map: req MemRegion* -> owning StackFrameContext*, meaning the req was
// successfully acquired (hwrm_req_init succeeded) in that stack frame and
// requires hwrm_req_drop() before exiting the frame.
REGISTER_MAP_WITH_PROGRAMSTATE(AcquiredReqsMap, const MemRegion *, const StackFrameContext *)

namespace {

static bool isCallToExact(const CallEvent &Call, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  return false;
}

static const StackFrameContext *getRegionOwnerFrame(const MemRegion *MR) {
  if (!MR)
    return nullptr;

  // Use the base region to strip element/field offsets.
  MR = MR->getBaseRegion();

  if (const auto *VR = dyn_cast<VarRegion>(MR))
    return VR->getStackFrame();

  // If it's not a VarRegion (e.g., globals), we can't attribute it to a frame.
  // Return nullptr so we won't report on unrelated frames.
  return nullptr;
}

static bool belongsToFrame(const MemRegion *MR, const StackFrameContext *SFC) {
  const StackFrameContext *Owner = getRegionOwnerFrame(MR);
  return Owner && Owner == SFC;
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
  // Helper that answers whether we have any acquired reqs in the current frame.
  bool hasAcquiredInCurrentFrame(ProgramStateRef State, const StackFrameContext *CurSFC) const;

  // Helper to purge all acquired reqs owned by the current frame from state.
  ProgramStateRef removeAllInCurrentFrame(ProgramStateRef State, const StackFrameContext *CurSFC) const;

  void reportLeak(CheckerContext &C, const Stmt *S) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (isCallToExact(Call, "hwrm_req_init")) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    if (!ReqExpr)
      return;

    const MemRegion *ReqMR = State->getSVal(ReqExpr, C.getLocationContext()).getAsRegion();
    if (!ReqMR)
      return;

    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;

    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (!RetSym)
      return;

    // Record pending init keyed by the return symbol.
    State = State->set<PendingInitMap>(RetSym, ReqMR);
    C.addTransition(State);
    return;
  }

  // Track hwrm_req_drop(bp, req)
  if (isCallToExact(Call, "hwrm_req_drop")) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ReqExpr = Call.getArgExpr(1);
    if (!ReqExpr)
      return;

    const MemRegion *ReqMR = State->getSVal(ReqExpr, C.getLocationContext()).getAsRegion();
    if (!ReqMR)
      return;
    ReqMR = ReqMR->getBaseRegion();
    if (!ReqMR)
      return;

    // Remove from acquired map if present.
    if (State->get<AcquiredReqsMap>(ReqMR)) {
      State = State->remove<AcquiredReqsMap>(ReqMR);
      C.addTransition(State);
    }
    return;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  // Case 1: plain symbolic condition like 'if (rc)'
  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    if (SymbolRef Sym = NL->getAsSymbol()) {
      if (const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym)) {
        // For 'if (rc)': Assumption == false means rc == 0 (success branch)
        if (!Assumption) {
          const MemRegion *ReqMR = *PendingReq;
          const StackFrameContext *Owner = getRegionOwnerFrame(ReqMR);
          if (Owner)
            State = State->set<AcquiredReqsMap>(ReqMR, Owner);
        }
        // Remove the pending mapping regardless of branch outcome.
        State = State->remove<PendingInitMap>(Sym);
      }
      return State;
    }

    // Case 2: comparison like (rc == 0) or (rc != 0)
    if (SymbolRef SE = Cond.getAsSymbol()) {
      if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        SymbolRef Sym = SIE->getLHS();
        const llvm::APSInt &RHS = SIE->getRHS();
        if (Sym) {
          if (const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym)) {
            if (RHS.isZero()) {
              bool SuccessBranch = false;
              if (Op == BO_EQ && Assumption)
                SuccessBranch = true;     // (rc == 0) assumed true
              else if (Op == BO_NE && !Assumption)
                SuccessBranch = true;     // (rc != 0) assumed false

              if (SuccessBranch) {
                const MemRegion *ReqMR = *PendingReq;
                const StackFrameContext *Owner = getRegionOwnerFrame(ReqMR);
                if (Owner)
                  State = State->set<AcquiredReqsMap>(ReqMR, Owner);
              }
            }
            State = State->remove<PendingInitMap>(Sym);
          }
        }
      }
    }
  }

  return State;
}

bool SAGenTestChecker::hasAcquiredInCurrentFrame(ProgramStateRef State,
                                                 const StackFrameContext *CurSFC) const {
  if (!CurSFC)
    return false;

  auto Map = State->get<AcquiredReqsMap>();
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    const MemRegion *MR = I->first;
    const StackFrameContext *Owner = I->second;
    if (Owner == CurSFC && MR)
      return true;
  }
  return false;
}

ProgramStateRef SAGenTestChecker::removeAllInCurrentFrame(ProgramStateRef State,
                                                          const StackFrameContext *CurSFC) const {
  if (!CurSFC)
    return State;

  auto Map = State->get<AcquiredReqsMap>();
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    const MemRegion *MR = I->first;
    const StackFrameContext *Owner = I->second;
    if (Owner == CurSFC && MR)
      State = State->remove<AcquiredReqsMap>(MR);
  }
  return State;
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  ProgramStateRef State = C.getState();
  const StackFrameContext *CurSFC = C.getLocationContext()->getStackFrame();

  // Only consider acquisitions owned by the current frame; this prevents
  // reporting in unrelated inlined callees (e.g., page_pool helpers).
  if (hasAcquiredInCurrentFrame(State, CurSFC)) {
    reportLeak(C, RS);
    // Clean up current frame acquisitions to avoid polluting outer frames.
    State = removeAllInCurrentFrame(State, CurSFC);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const StackFrameContext *CurSFC = C.getLocationContext()->getStackFrame();

  if (hasAcquiredInCurrentFrame(State, CurSFC)) {
    reportLeak(C, nullptr);
  }

  // Always purge current frame acquisitions at end of function to prevent
  // state bleed into callers/callees.
  State = removeAllInCurrentFrame(State, CurSFC);
  C.addTransition(State);
}

void SAGenTestChecker::reportLeak(CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing hwrm_req_drop() after successful hwrm_req_init()", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "{{Checker descriptions to be filled}}",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
