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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states:
// - SQPendingRdyMap: sq region -> mdev region, indicates set_sq_rdy was just invoked for this SQ.
// - RetSymToSQMap: return SymbolRef of set_sq_rdy -> sq region.
// - ErrVarToSQMap: region of variable storing the return of set_sq_rdy (e.g., 'err') -> sq region.
REGISTER_MAP_WITH_PROGRAMSTATE(SQPendingRdyMap, const MemRegion*, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(RetSymToSQMap, SymbolRef, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToSQMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Wrong cleanup in error path", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C);

  const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

  // Extract the SQ region from the 2nd argument of hws_send_ring_set_sq_rdy(..., sq->sqn)
  const MemRegion *extractSQRegionFromSetRdyArg(const CallEvent &Call, CheckerContext &C) const;

  void reportWrongCleanup(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

const MemRegion *SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

const MemRegion *SAGenTestChecker::extractSQRegionFromSetRdyArg(const CallEvent &Call, CheckerContext &C) const {
  if (Call.getNumArgs() < 2)
    return nullptr;

  const Expr *Arg1 = Call.getArgExpr(1);
  if (!Arg1)
    return nullptr;

  // We expect something like sq->sqn; find MemberExpr named "sqn", then get its base (the 'sq')
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg1);
  if (!ME)
    return nullptr;

  const ValueDecl *MD = ME->getMemberDecl();
  if (!MD)
    return nullptr;

  if (MD->getName() != "sqn")
    return nullptr;

  const Expr *Base = ME->getBase();
  if (!Base)
    return nullptr;

  return getBaseRegionFromExpr(Base, C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track hws_send_ring_set_sq_rdy(mdev, sq->sqn)
  if (isCallNamed(Call, "hws_send_ring_set_sq_rdy", C)) {
    // mdev region from arg[0]
    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *MdevReg = getBaseRegionFromExpr(Arg0, C);
    if (!MdevReg)
      return;

    // sq region derived from arg[1]
    const MemRegion *SQReg = extractSQRegionFromSetRdyArg(Call, C);
    if (!SQReg)
      return;

    // Record that this SQ is pending ready, paired with its mdev
    State = State->set<SQPendingRdyMap>(SQReg, MdevReg);

    // Map the return symbol to the SQ
    SVal Ret = Call.getReturnValue();
    if (SymbolRef Sym = Ret.getAsSymbol()) {
      State = State->set<RetSymToSQMap>(Sym, SQReg);
    }

    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (const MemRegion *const *SQRegPtr = State->get<RetSymToSQMap>(Sym)) {
      const MemRegion *SQReg = *SQRegPtr;
      // Bind err-like variable region to the SQ region
      State = State->set<ErrVarToSQMap>(LHSReg, SQReg);
      // Consume the return symbol mapping
      State = State->remove<RetSymToSQMap>(Sym);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::reportWrongCleanup(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use destroy for partially initialized SQ; 'close' here may double free.", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Correct cleanup: hws_send_ring_destroy_sq(mdev, sq)
  if (isCallNamed(Call, "hws_send_ring_destroy_sq", C)) {
    if (Call.getNumArgs() >= 2) {
      const Expr *Arg1 = Call.getArgExpr(1);
      if (const MemRegion *SQReg = getBaseRegionFromExpr(Arg1, C)) {
        // Cleanup: no need to warn, remove pending state if exists.
        if (State->get<SQPendingRdyMap>(SQReg)) {
          State = State->remove<SQPendingRdyMap>(SQReg);
          C.addTransition(State);
        }
      }
    }
    return;
  }

  // Misuse we want to catch: hws_send_ring_close_sq(sq) inside error branch after set_sq_rdy
  if (isCallNamed(Call, "hws_send_ring_close_sq", C)) {
    if (Call.getNumArgs() < 1)
      return;

    // Extract SQ region from arg[0]
    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *SQReg = getBaseRegionFromExpr(Arg0, C);
    if (!SQReg)
      return;

    // Only consider SQs that are in "pending ready" state
    const MemRegion *const *MdevRegPtr = State->get<SQPendingRdyMap>(SQReg);
    if (!MdevRegPtr)
      return;
    const MemRegion *MdevReg = *MdevRegPtr;
    (void)MdevReg; // MdevReg is not used further, keep semantics explicit.

    // Find nearest IfStmt containing this call: ensure it's in an error branch
    const Expr *Origin = Call.getOriginExpr();
    if (!Origin)
      return;

    const IfStmt *IfP = findSpecificTypeInParents<IfStmt>(Origin, C);
    if (!IfP)
      return;

    // Heuristic: find a DeclRefExpr in condition (e.g., 'err')
    const Expr *CondE = IfP->getCond();
    if (!CondE)
      return;

    const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(CondE);
    if (!DRE)
      return;

    const Expr *CondVarE = DRE;
    const MemRegion *CondVarReg = getBaseRegionFromExpr(CondVarE, C);
    if (!CondVarReg)
      return;

    // Check if this condition var is mapped to the same SQ (from set_sq_rdy result)
    const MemRegion *const *MappedSQPtr = State->get<ErrVarToSQMap>(CondVarReg);
    if (!MappedSQPtr)
      return;
    const MemRegion *MappedSQ = *MappedSQPtr;

    if (MappedSQ == SQReg) {
      // This is exactly the misuse we target.
      reportWrongCleanup(Call, C);
      // Avoid duplicate reports along this path
      State = State->remove<SQPendingRdyMap>(SQReg);
      C.addTransition(State);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects using close() instead of destroy() in the error path after set_sq_rdy, which may double free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
