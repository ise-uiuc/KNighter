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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Location,
        check::Bind> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this, "Use-after-free after release call",
                                     "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  const MemRegion *canon(const MemRegion *R, ProgramStateRef State) const;
  bool functionMayFreeParam(const CallEvent &Call,
                            llvm::SmallVectorImpl<unsigned> &FreeParams,
                            CheckerContext &C) const;
  void reportUAF(const Stmt *S, CheckerContext &C,
                 const char *Msg) const;
};

// Canonicalize a region via simple alias map following.
const MemRegion *SAGenTestChecker::canon(const MemRegion *R, ProgramStateRef State) const {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  // Follow alias chain until fixed point.
  llvm::SmallPtrSet<const MemRegion *, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break;
    const MemRegion *Next = State->get<PtrAliasMap>(Cur);
    if (!Next || Next == Cur)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur ? Cur->getBaseRegion() : nullptr;
}

// Identify functions that may free their pointer arguments.
bool SAGenTestChecker::functionMayFreeParam(const CallEvent &Call,
                                            llvm::SmallVectorImpl<unsigned> &FreeParams,
                                            CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  bool Found = false;

  // mptcp_close_ssk(sk, ssk, subflow) -> frees 'subflow' (idx 2)
  if (ExprHasName(Origin, "mptcp_close_ssk", C)) {
    FreeParams.push_back(2);
    Found = true;
  }

  // Generic free helpers.
  if (ExprHasName(Origin, "kfree", C)) {
    FreeParams.push_back(0);
    Found = true;
  }
  if (ExprHasName(Origin, "kvfree", C)) {
    FreeParams.push_back(0);
    Found = true;
  }

  return Found;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  llvm::SmallVector<unsigned, 4> FreeParams;
  if (!functionMayFreeParam(Call, FreeParams, C))
    return;

  for (unsigned Idx : FreeParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    const MemRegion *Can = canon(MR, State);
    if (!Can)
      Can = MR;

    State = State->set<ReleasedMap>(Can, true);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // If a function is known to dereference certain parameters, ensure none
  // of those arguments were previously marked as released.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    const MemRegion *Can = canon(MR, State);
    if (!Can)
      Can = MR;

    const bool *Released = State->get<ReleasedMap>(Can);
    if (Released && *Released) {
      reportUAF(Call.getOriginExpr(), C,
                "Use-after-free: passing freed pointer to dereferencing function");
      return;
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // We are primarily interested in reads of freed objects (e.g., subflow->field).
  if (!IsLoad)
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Can = canon(R, State);
  if (!Can)
    Can = R;

  const bool *Released = State->get<ReleasedMap>(Can);
  if (Released && *Released) {
    reportUAF(S, C, "Use-after-free: field read of freed object");
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }

  if (const MemRegion *ValReg = Val.getAsRegion()) {
    ValReg = ValReg->getBaseRegion();
    if (ValReg) {
      const MemRegion *Can = canon(ValReg, State);
      if (!Can)
        Can = ValReg;
      State = State->set<PtrAliasMap>(LHSReg, Can);
      C.addTransition(State);
      return;
    }
  }

  // If RHS is not a region (e.g., NULL, integer, unknown), drop alias info.
  State = State->remove<PtrAliasMap>(LHSReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportUAF(const Stmt *S, CheckerContext &C,
                                 const char *Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free when accessing a structure after a release/close call (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
