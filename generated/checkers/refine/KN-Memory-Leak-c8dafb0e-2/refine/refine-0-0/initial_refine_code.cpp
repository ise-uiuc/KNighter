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
// Map: rc variable region -> req MemRegion* (when rc = hwrm_req_init(...))
REGISTER_MAP_WITH_PROGRAMSTATE(PendingInitByVar, const MemRegion *, const MemRegion *)

namespace {

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    return ID->getName() == Name;
  }
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Fallback for macro/wrapper cases.
  return ExprHasName(Origin, Name, C);
}

static const FunctionDecl *getOwningFunctionOfRegion(const MemRegion *MR) {
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;

  if (const auto *VR = dyn_cast<VarRegion>(MR)) {
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      return nullptr;
    const DeclContext *DC = VD->getDeclContext();
    return dyn_cast_or_null<FunctionDecl>(const_cast<DeclContext *>(DC));
  }
  return nullptr;
}

static bool isOwnedByCurrentFunction(const MemRegion *MR, CheckerContext &C) {
  const FunctionDecl *CurFD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  const FunctionDecl *OwnerFD = getOwningFunctionOfRegion(MR);
  return CurFD && OwnerFD && CurFD == OwnerFD;
}

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreStmt<ReturnStmt>,
    check::EndFunction,
    check::Bind,
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
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

   private:

      void reportLeak(CheckerContext &C, const Stmt *S) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (isCallTo(Call, "hwrm_req_init", C)) {
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

    // Record pending init: we'll determine success in evalAssume or via rc var.
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

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If a variable is being bound to the return symbol of hwrm_req_init(),
  // remember the variable region -> req mapping, so that later 'if (rc)'
  // conditions can be recognized in evalAssume.
  SymbolRef RHSym = Val.getAsSymbol();
  if (!RHSym)
    return;

  const MemRegion *const *PendingReq = State->get<PendingInitMap>(RHSym);
  if (!PendingReq)
    return;

  const MemRegion *DstR = Loc.getAsRegion();
  if (!DstR)
    return;
  DstR = DstR->getBaseRegion();
  if (!DstR)
    return;

  // Map the destination variable region (e.g., rc) to the req region.
  State = State->set<PendingInitByVar>(DstR, *PendingReq);
  C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  auto markSuccessForReq = [&](const MemRegion *ReqMR) -> ProgramStateRef {
    if (!ReqMR)
      return State;
    // Record the req as acquired (needs a drop).
    if (!State->contains<AcquiredReqs>(ReqMR))
      State = State->add<AcquiredReqs>(ReqMR);
    return State;
  };

  // Handle conditions:
  //  - 'if (rc)' or 'if (!rc)' where 'rc' is a SymbolRegionValue.
  //  - 'if (rc == 0)' / 'if (rc != 0)' as SymIntExpr with RHS == 0.
  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    if (SymbolRef Sym = NL->getAsSymbol()) {
      // Case A: raw symbolic rc (SymbolRegionValue), condition 'if (rc)'
      if (const auto *SRV = dyn_cast<SymbolRegionValue>(Sym)) {
        const MemRegion *RCVarR = SRV->getRegion();
        if (RCVarR) {
          RCVarR = RCVarR->getBaseRegion();
          if (const MemRegion *const *ReqMR = State->get<PendingInitByVar>(RCVarR)) {
            // if (rc) with Assumption == false means rc == 0 (success)
            if (!Assumption) {
              State = markSuccessForReq(*ReqMR);
            }
            // Either way, we don't need the pending var mapping anymore.
            State = State->remove<PendingInitByVar>(RCVarR);
          }
        }
      }

      // Case B: condition carries the original return symbol from init call
      // 'if (hwrm_req_init(...))' or equivalent.
      if (const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym)) {
        if (!Assumption) {
          State = markSuccessForReq(*PendingReq);
        }
        State = State->remove<PendingInitMap>(Sym);
      }

      // Case C: SymIntExpr like 'rc == 0' / 'rc != 0'
      if (const auto *SIE = dyn_cast<SymIntExpr>(Sym)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        const llvm::APSInt &RHS = SIE->getRHS();
        SymbolRef LHS = SIE->getLHS();
        if (RHS == 0 && LHS) {
          // lhs may be a variable symbol or a return symbol
          // First try variable mapping (rc variable)
          if (const auto *LSRV = dyn_cast<SymbolRegionValue>(LHS)) {
            const MemRegion *RCVarR = LSRV->getRegion();
            if (RCVarR) {
              RCVarR = RCVarR->getBaseRegion();
              if (const MemRegion *const *ReqMR = State->get<PendingInitByVar>(RCVarR)) {
                bool SuccessBranch = false;
                if (Op == BO_EQ && Assumption)
                  SuccessBranch = true;        // (rc == 0) assumed true
                else if (Op == BO_NE && !Assumption)
                  SuccessBranch = true;        // (rc != 0) assumed false

                if (SuccessBranch)
                  State = markSuccessForReq(*ReqMR);

                State = State->remove<PendingInitByVar>(RCVarR);
              }
            }
          }

          // Then try return-symbol mapping
          if (const MemRegion *const *PendingReq = State->get<PendingInitMap>(LHS)) {
            bool SuccessBranch = false;
            if (Op == BO_EQ && Assumption)
              SuccessBranch = true;        // (ret == 0) assumed true
            else if (Op == BO_NE && !Assumption)
              SuccessBranch = true;        // (ret != 0) assumed false

            if (SuccessBranch)
              State = markSuccessForReq(*PendingReq);

            State = State->remove<PendingInitMap>(LHS);
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
  auto Set = State->get<AcquiredReqs>();
  if (Set.isEmpty())
    return;

  // Only report if the acquired req belongs to the same function being returned from.
  llvm::SmallVector<const MemRegion *, 4> OwnedReqsInThisFn;
  for (const MemRegion *ReqMR : Set) {
    if (isOwnedByCurrentFunction(ReqMR, C))
      OwnedReqsInThisFn.push_back(ReqMR);
  }

  if (!OwnedReqsInThisFn.empty()) {
    // Report once for this return site.
    reportLeak(C, RS);

    // Clean up the reqs owned by this function to avoid duplicate reports on path exit.
    for (const MemRegion *ReqMR : OwnedReqsInThisFn)
      State = State->remove<AcquiredReqs>(ReqMR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  auto Set = State->get<AcquiredReqs>();
  if (Set.isEmpty())
    return;

  llvm::SmallVector<const MemRegion *, 4> OwnedReqsInThisFn;
  for (const MemRegion *ReqMR : Set) {
    if (isOwnedByCurrentFunction(ReqMR, C))
      OwnedReqsInThisFn.push_back(ReqMR);
  }

  if (!OwnedReqsInThisFn.empty()) {
    reportLeak(C, nullptr);
    for (const MemRegion *ReqMR : OwnedReqsInThisFn)
      State = State->remove<AcquiredReqs>(ReqMR);
    C.addTransition(State);
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
