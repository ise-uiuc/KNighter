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

// Map: return-symbol of hwrm_req_init() -> owner function Decl where init occurred
REGISTER_MAP_WITH_PROGRAMSTATE(PendingInitOwnerMap, SymbolRef, const Decl *)

// Map of acquired request MemRegion -> owning function Decl.
// We only report when returning from (or ending) that owning function.
REGISTER_MAP_WITH_PROGRAMSTATE(AcquiredReqMap, const MemRegion *, const Decl *)

namespace {

static bool callIsNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    return ID->getName() == Name;
  }
  // Fallback for macro wrappers or when identifier not directly available.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

static const Decl *getCurrentFunctionDecl(const CheckerContext &C) {
  const LocationContext *LCtx = C.getLocationContext();
  const StackFrameContext *SFC = LCtx ? LCtx->getStackFrame() : nullptr;
  return SFC ? SFC->getDecl() : nullptr;
}

static bool isInSystemHeader(const Stmt *S, CheckerContext &C) {
  if (!S)
    return false;
  const SourceManager &SM = C.getSourceManager();
  return SM.isInSystemHeader(S->getBeginLoc());
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
            "Missing hwrm_req_drop() after successful hwrm_req_init()",
            "Resource management");
      }

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
      ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;

   private:
      void reportLeak(CheckerContext &C, const Stmt *S) const;

      static bool hasOutstandingForOwner(ProgramStateRef State, const Decl *Owner);
      static ProgramStateRef removeAllForOwner(ProgramStateRef State, const Decl *Owner);
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hwrm_req_init(bp, req, ...)
  if (callIsNamed(Call, "hwrm_req_init", C)) {
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

    const Decl *OwnerD = getCurrentFunctionDecl(C);
    // Record pending init: we'll determine success in evalAssume
    State = State->set<PendingInitMap>(RetSym, ReqMR);
    State = State->set<PendingInitOwnerMap>(RetSym, OwnerD);
    C.addTransition(State);
    return;
  }

  // Track hwrm_req_drop(bp, req)
  if (callIsNamed(Call, "hwrm_req_drop", C)) {
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

    // On drop, remove from acquired map (if present)
    if (State->get<AcquiredReqMap>(ReqMR)) {
      State = State->remove<AcquiredReqMap>(ReqMR);
      C.addTransition(State);
    }
    return;
  }
}

// Helper: check if there are any acquisitions owned by this function.
bool SAGenTestChecker::hasOutstandingForOwner(ProgramStateRef State, const Decl *Owner) {
  if (!Owner)
    return false;
  auto Map = State->get<AcquiredReqMap>();
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    if (I->second == Owner)
      return true;
  }
  return false;
}

// Helper: remove all acquisitions owned by this function (to keep state small).
ProgramStateRef SAGenTestChecker::removeAllForOwner(ProgramStateRef State, const Decl *Owner) {
  if (!Owner)
    return State;
  auto Map = State->get<AcquiredReqMap>();
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    if (I->second == Owner)
      State = State->remove<AcquiredReqMap>(I->first);
  }
  return State;
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  if (!State)
    return State;

  // Case 1: plain symbolic condition, e.g., if (rc)
  if (std::optional<NonLoc> NL = Cond.getAs<NonLoc>()) {
    if (SymbolRef Sym = NL->getAsSymbol()) {
      const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
      const Decl *const *OwnerD = State->get<PendingInitOwnerMap>(Sym);
      if (PendingReq && OwnerD) {
        // For "if (rc)", false branch means rc == 0 (success).
        if (!Assumption) {
          State = State->set<AcquiredReqMap>(*PendingReq, *OwnerD);
        }
        State = State->remove<PendingInitMap>(Sym);
        State = State->remove<PendingInitOwnerMap>(Sym);
      }
      return State;
    }

    // Case 2: comparison against integer (rc == 0) or (rc != 0).
    if (SymbolRef SE = Cond.getAsSymbol()) {
      if (const auto *SIE = dyn_cast<SymIntExpr>(SE)) {
        BinaryOperator::Opcode Op = SIE->getOpcode();
        SymbolRef Sym = SIE->getLHS();
        const llvm::APSInt &RHS = SIE->getRHS();
        if (Sym && RHS == 0) {
          const MemRegion *const *PendingReq = State->get<PendingInitMap>(Sym);
          const Decl *const *OwnerD = State->get<PendingInitOwnerMap>(Sym);
          if (PendingReq && OwnerD) {
            bool SuccessBranch = false;
            if (Op == BO_EQ && Assumption)
              SuccessBranch = true;        // (rc == 0) assumed true
            else if (Op == BO_NE && !Assumption)
              SuccessBranch = true;        // (rc != 0) assumed false

            if (SuccessBranch) {
              State = State->set<AcquiredReqMap>(*PendingReq, *OwnerD);
            }
            State = State->remove<PendingInitMap>(Sym);
            State = State->remove<PendingInitOwnerMap>(Sym);
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

  // Heuristic: don't report from returns inside system headers.
  if (isInSystemHeader(RS, C))
    return;

  ProgramStateRef State = C.getState();
  const Decl *CurOwner = getCurrentFunctionDecl(C);

  // Only report when returning from the function that owns the outstanding req.
  if (hasOutstandingForOwner(State, CurOwner)) {
    reportLeak(C, RS);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Decl *CurOwner = getCurrentFunctionDecl(C);

  if (hasOutstandingForOwner(State, CurOwner)) {
    // For functions without an explicit return, still report.
    reportLeak(C, RS);
    // Clean up to keep state bounded and avoid cascading reports.
    State = removeAllForOwner(State, CurOwner);
    C.addTransition(State);
  }

  // Also clear any pending init info for return symbols that didn't get assumed.
  // This prevents stale state flowing out of this function.
  // We cannot iterate PendingInitMap by owner easily, so leave it; it is harmless
  // because acquisitions only happen via evalAssume, but we keep Acquired map clean.
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
