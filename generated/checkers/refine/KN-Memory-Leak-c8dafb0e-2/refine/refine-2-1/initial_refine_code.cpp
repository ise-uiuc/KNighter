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

// Set: req MemRegions that had a successful hwrm_req_init()
REGISTER_SET_WITH_PROGRAMSTATE(OpenInitReqs, const MemRegion *)

// Set: req MemRegions that require hwrm_req_drop() because of hold/replace
REGISTER_SET_WITH_PROGRAMSTATE(NeedsDropReqs, const MemRegion *)

namespace {

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

static const MemRegion *getReqRegionFromArg(const CallEvent &Call,
                                            unsigned ArgIdx,
                                            CheckerContext &C) {
  if (Call.getNumArgs() <= ArgIdx)
    return nullptr;
  const Expr *ReqExpr = Call.getArgExpr(ArgIdx);
  if (!ReqExpr)
    return nullptr;
  const MemRegion *ReqMR = getMemRegionFromExpr(ReqExpr, C);
  if (!ReqMR)
    return nullptr;
  return ReqMR->getBaseRegion();
}

/* The checker callbacks are to be decided. */
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
      void reportLeak(CheckerContext &C, const Stmt *S) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Track hwrm_req_init(bp, req, ...)
  if (isCallTo(Call, "hwrm_req_init", C)) {
    // Ensure we have at least 2 args: 0: bp, 1: req
    const MemRegion *ReqMR = getReqRegionFromArg(Call, 1, C);
    if (!ReqMR)
      return;

    // Record pending init: we'll determine success in evalAssume
    if (SymbolRef RetSym = Call.getReturnValue().getAsSymbol()) {
      State = State->set<PendingInitMap>(RetSym, ReqMR);
      Changed = true;
    }
  }

  // Track hwrm_req_hold(bp, req) => requires drop if there was a successful init
  if (isCallTo(Call, "hwrm_req_hold", C)) {
    const MemRegion *ReqMR = getReqRegionFromArg(Call, 1, C);
    if (ReqMR && State->get<OpenInitReqs>().contains(ReqMR)) {
      State = State->add<NeedsDropReqs>(ReqMR);
      Changed = true;
    }
  }

  // Track hwrm_req_replace(bp, req, ...) => requires drop if there was a successful init,
  // regardless of replace rc (matches the bug pattern/fix)
  if (isCallTo(Call, "hwrm_req_replace", C)) {
    const MemRegion *ReqMR = getReqRegionFromArg(Call, 1, C);
    if (ReqMR && State->get<OpenInitReqs>().contains(ReqMR)) {
      State = State->add<NeedsDropReqs>(ReqMR);
      Changed = true;
    }
  }

  // Track hwrm_req_send(bp, req)
  // If this is a simple init+send path (no hold/replace), no drop is required.
  // So we can clear OpenInit state (but keep NeedsDrop if present).
  if (isCallTo(Call, "hwrm_req_send", C)) {
    const MemRegion *ReqMR = getReqRegionFromArg(Call, 1, C);
    if (ReqMR) {
      auto OpenSet = State->get<OpenInitReqs>();
      auto NeedSet = State->get<NeedsDropReqs>();
      if (OpenSet.contains(ReqMR) && !NeedSet.contains(ReqMR)) {
        State = State->remove<OpenInitReqs>(ReqMR);
        Changed = true;
      }
    }
  }

  // Track hwrm_req_drop(bp, req)
  if (isCallTo(Call, "hwrm_req_drop", C)) {
    const MemRegion *ReqMR = getReqRegionFromArg(Call, 1, C);
    if (ReqMR) {
      if (State->get<OpenInitReqs>().contains(ReqMR)) {
        State = State->remove<OpenInitReqs>(ReqMR);
        Changed = true;
      }
      if (State->get<NeedsDropReqs>().contains(ReqMR)) {
        State = State->remove<NeedsDropReqs>(ReqMR);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  auto consumePendingInit = [&](SymbolRef Sym, bool Success) -> ProgramStateRef {
    if (!Sym)
      return State;
    const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
    if (!PendingReq)
      return State;

    ProgramStateRef NewState = State->remove<PendingInitMap>(Sym);
    if (Success) {
      NewState = NewState->add<OpenInitReqs>(*PendingReq);
    }
    return NewState;
  };

  // Handle symbolic condition patterns for rc checks
  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    // Case 1: plain symbolic value 'rc'
    if (SymbolRef Sym = NL->getAsSymbol()) {
      // if (rc) and Assumption == false => rc == 0 (success)
      bool Success = !Assumption;
      return consumePendingInit(Sym, Success);
    }

    // Case 2: symbolic int comparison, e.g., (rc == 0) or (rc != 0)
    if (SymbolRef SE = Cond.getAsSymbol()) {
      if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        SymbolRef Sym = SIE->getLHS();
        const llvm::APSInt &RHS = SIE->getRHS();
        if (RHS == 0 && Sym) {
          bool SuccessBranch = false;
          if (Op == BO_EQ && Assumption)
            SuccessBranch = true;        // (rc == 0) assumed true
          else if (Op == BO_NE && !Assumption)
            SuccessBranch = true;        // (rc != 0) assumed false

          return consumePendingInit(Sym, SuccessBranch);
        }
      }
    }
  }

  return State;
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  ProgramStateRef State = C.getState();
  if (!State->get<NeedsDropReqs>().isEmpty()) {
    reportLeak(C, RS);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State->get<NeedsDropReqs>().isEmpty()) {
    reportLeak(C, nullptr);
  }
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
