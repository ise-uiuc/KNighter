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

using namespace clang;
using namespace ento;
using namespace taint;

// Track base regions that were freed/destroyed by a close-like call.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedRegionMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::Location> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Use-after-free after close-like call", "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper: get the base region of the pointee from a call argument.
  static const MemRegion *getPointeeBaseRegionFromArg(const CallEvent &Call, unsigned Idx, CheckerContext &C);

  // Helper: get the base region from a location SVal.
  static const MemRegion *getBaseFromLocSVal(SVal Loc);

  // Helper: identify close/free-like calls and return the index of the pointer that gets freed.
  static bool isCloseLikeCall(const CallEvent &Call, unsigned &FreedParamIdx, CheckerContext &C);

  // Reporting helpers
  void reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const;
  void reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
};

const MemRegion *SAGenTestChecker::getPointeeBaseRegionFromArg(const CallEvent &Call,
                                                               unsigned Idx,
                                                               CheckerContext &C) {
  if (Idx >= Call.getNumArgs())
    return nullptr;

  // Prefer using the expression to retrieve a region if possible.
  const Expr *ArgE = Call.getArgExpr(Idx);
  const MemRegion *MR = nullptr;
  if (ArgE)
    MR = getMemRegionFromExpr(ArgE, C);

  if (!MR) {
    // Fallback to using the SVal of the argument.
    SVal V = Call.getArgSVal(Idx);
    MR = V.getAsRegion();
  }

  if (!MR)
    return nullptr;

  MR = MR->getBaseRegion();
  return MR;
}

const MemRegion *SAGenTestChecker::getBaseFromLocSVal(SVal Loc) {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

bool SAGenTestChecker::isCloseLikeCall(const CallEvent &Call,
                                       unsigned &FreedParamIdx,
                                       CheckerContext &C) {
  // We identify mptcp_close_ssk(sk, ssk, subflow), which frees/destroys 'subflow'.
  FreedParamIdx = 2; // the 'subflow' argument
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  if (ExprHasName(OriginExpr, "mptcp_close_ssk", C))
    return true;

  return false;
}

void SAGenTestChecker::reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

// Mark freed/destroyed objects after close-like calls.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned FreedIdx = 0;
  if (!isCloseLikeCall(Call, FreedIdx, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *FreedBase = getPointeeBaseRegionFromArg(Call, FreedIdx, C);
  if (!FreedBase)
    return;

  State = State->set<FreedRegionMap>(FreedBase, true);
  C.addTransition(State);
}

// Detect passing freed objects to functions that are known to dereference them.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    const MemRegion *Base = getPointeeBaseRegionFromArg(Call, Idx, C);
    if (!Base)
      continue;

    const bool *WasFreed = State->get<FreedRegionMap>(Base);
    if (Wasfreed && *WasFreed) {
      reportUAFAtCall(Call, C, "Use-after-free: freed object passed to a function that dereferences it");
      // Continue checking other parameters; do not early return.
    }
  }
}

// Detect any load/store from a region whose base was marked as freed.
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  const MemRegion *Base = getBaseFromLocSVal(Loc);
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  const bool *WasFreed = State->get<FreedRegionMap>(Base);
  if (WasFreed && *WasFreed) {
    reportUAFAtStmt(S, C, "Use-after-free: object accessed after mptcp_close_ssk");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free when accessing subflow objects after mptcp_close_ssk",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
