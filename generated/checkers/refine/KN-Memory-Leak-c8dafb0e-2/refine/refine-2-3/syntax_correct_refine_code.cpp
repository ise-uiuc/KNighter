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
// Set: Acquired req MemRegion*s that require hwrm_req_drop() before exiting
REGISTER_SET_WITH_PROGRAMSTATE(AcquiredReqs, const MemRegion *)

namespace {

static bool isCallNamed(const CallEvent &Call, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    return ID->getName() == Name;
  }
  return false;
}

static const MemRegion *getReqBaseRegionFromArg(const CallEvent &Call,
                                                unsigned ArgIdx,
                                                CheckerContext &C) {
  if (Call.getNumArgs() <= ArgIdx)
    return nullptr;
  const Expr *ArgE = Call.getArgExpr(ArgIdx);
  if (!ArgE)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

static const StackFrameContext *getOwningFrameOfRegion(const MemRegion *MR) {
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (const auto *VR = dyn_cast<VarRegion>(MR))
    return VR->getStackFrame();
  return nullptr;
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
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                             bool Assumption) const;

private:
  void reportLeaksInCurrentFrame(CheckerContext &C, const Stmt *S) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (isCallNamed(Call, "hwrm_req_init")) {
    // Get the 'req' arg (index 1)
    const MemRegion *ReqMR = getReqBaseRegionFromArg(Call, 1, C);
    if (!ReqMR)
      return;

    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (!RetSym)
      return;

    // Record pending init keyed by the return symbol; we'll confirm success in evalAssume().
    State = State->set<PendingInitMap>(RetSym, ReqMR);
    C.addTransition(State);
    return;
  }

  // Track hwrm_req_drop(bp, req)
  if (isCallNamed(Call, "hwrm_req_drop")) {
    const MemRegion *ReqMR = getReqBaseRegionFromArg(Call, 1, C);
    if (!ReqMR)
      return;

    auto Set = State->get<AcquiredReqs>();
    if (Set.contains(ReqMR)) {
      State = State->remove<AcquiredReqs>(ReqMR);
      C.addTransition(State);
    }
    return;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond,
                                             bool Assumption) const {
  if (!State)
    return State;

  // We want to detect when "ret == 0" (success) for the return value symbol
  // of hwrm_req_init() that we saved in PendingInitMap. Then, we move the
  // associated req MemRegion* to AcquiredReqs.
  auto TransferOnSuccess = [&](SymbolRef Sym, bool IsSuccess) -> ProgramStateRef {
    if (!Sym)
      return State;
    const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
    if (!PendingReq)
      return State;
    ProgramStateRef NewState = State->remove<PendingInitMap>(Sym);
    if (IsSuccess) {
      NewState = NewState->add<AcquiredReqs>(*PendingReq);
    }
    return NewState;
  };

  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    // Case 1: if (rc)
    if (SymbolRef Sym = NL->getAsSymbol()) {
      // if (rc) being assumed false means rc == 0 (success path)
      State = TransferOnSuccess(Sym, /*IsSuccess=*/!Assumption);
      return State;
    }

    // Case 2: if (rc == 0) or if (rc != 0)
    if (SymbolRef SE = Cond.getAsSymbol()) {
      if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        SymbolRef LHS = SIE->getLHS();
        const llvm::APSInt &RHS = SIE->getRHS();
        if (RHS == 0 && LHS) {
          bool SuccessBranch = false;
          if (Op == BO_EQ && Assumption)
            SuccessBranch = true;   // (rc == 0) assumed true
          else if (Op == BO_NE && !Assumption)
            SuccessBranch = true;   // (rc != 0) assumed false
          State = TransferOnSuccess(LHS, SuccessBranch);
          return State;
        }
      }
    }
  }

  return State;
}

void SAGenTestChecker::reportLeaksInCurrentFrame(CheckerContext &C,
                                                 const Stmt *S) const {
  ProgramStateRef State = C.getState();
  const StackFrameContext *CurFrame = C.getStackFrame();

  // Filter AcquiredReqs to only those whose owning frame matches CurFrame
  llvm::SmallVector<const MemRegion *, 4> LeakedHere;
  for (const MemRegion *MR : State->get<AcquiredReqs>()) {
    if (getOwningFrameOfRegion(MR) == CurFrame)
      LeakedHere.push_back(MR);
  }

  if (LeakedHere.empty())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing hwrm_req_drop() after successful hwrm_req_init()", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;
  // Only report leaks owned by the current frame; this avoids spurious
  // reports from inlined helper functions (e.g., in headers).
  reportLeaksInCurrentFrame(C, RS);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  // Only report leaks owned by the current frame; this ensures we report
  // at the end of the function that performed hwrm_req_init().
  reportLeaksInCurrentFrame(C, RS);
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
