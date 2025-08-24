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
// Set: Acquired req MemRegion*s that require hwrm_req_drop() before exit
REGISTER_SET_WITH_PROGRAMSTATE(AcquiredReqs, const MemRegion *)

namespace {

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
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
      void checkEndFunction(CheckerContext &C) const;
      ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

   private:

      void reportLeak(CheckerContext &C, const Stmt *S) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (isCallTo(Call, "hwrm_req_init", C)) {
    // Ensure we have at least 2 args: 0: bp, 1: req
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

    // Record pending init: we'll determine success in evalAssume
    State = State->set<PendingInitMap>(RetSym, ReqMR);
    C.addTransition(State);
    return;
  }

  // Track hwrm_req_drop(bp, req)
  if (isCallTo(Call, "hwrm_req_drop", C)) {
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

    // On drop, remove from acquired set (if present)
    auto Set = State->get<AcquiredReqs>();
    if (Set.contains(ReqMR)) {
      State = State->remove<AcquiredReqs>(ReqMR);
      C.addTransition(State);
    }
    return;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  // Handle pattern: if (rc) or if (!rc) or if (rc == 0) / if (rc != 0)
  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    // Case 1: plain symbolic value 'rc'
    if (SymbolRef Sym = NL->getAsSymbol()) {
      const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
      if (PendingReq) {
        // if (rc) with Assumption == false means rc == 0 (success)
        if (!Assumption) {
          State = State->add<AcquiredReqs>(*PendingReq);
        }
        // Consume the pending mapping either way
        State = State->remove<PendingInitMap>(Sym);
      }
      return State;
    }

    // Case 2: symbolic comparison with integer, usually rc == 0 or rc != 0
    if (const SymExpr *SE = NL->getAsSymExpr()) {
      if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        SymbolRef Sym = SIE->getLHS();
        const llvm::APSInt &RHS = SIE->getRHS();
        if (Sym) {
          const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
          if (PendingReq && RHS == 0) {
            bool SuccessBranch = false;
            if (Op == BO_EQ && Assumption)
              SuccessBranch = true;        // (rc == 0) assumed true
            else if (Op == BO_NE && !Assumption)
              SuccessBranch = true;        // (rc != 0) assumed false

            if (SuccessBranch) {
              State = State->add<AcquiredReqs>(*PendingReq);
            }
            State = State->remove<PendingInitMap>(Sym);
          }
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
  // If any acquired req is still live, report a leak.
  if (!State->get<AcquiredReqs>().isEmpty()) {
    reportLeak(C, RS);
  }
}

void SAGenTestChecker::checkEndFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State->get<AcquiredReqs>().isEmpty()) {
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
```
