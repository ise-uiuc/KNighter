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

// Program state: set of regions that have been released/closed.
REGISTER_SET_WITH_PROGRAMSTATE(ReleasedRegions, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<
                           check::PostCall,
                           check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-close read", "Memory Error")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      // Helper: known functions that release/close their pointer parameters.
      bool functionKnownToRelease(const CallEvent &Call,
                                  llvm::SmallVectorImpl<unsigned> &RelParams,
                                  CheckerContext &C) const;

      void reportUAF(const Stmt *S, CheckerContext &C) const;
};

bool SAGenTestChecker::functionKnownToRelease(const CallEvent &Call,
                                              llvm::SmallVectorImpl<unsigned> &RelParams,
                                              CheckerContext &C) const {
  // Use ExprHasName for robust name checking.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Target: mptcp_close_ssk(sk, ssk, subflow)
  // The 3rd parameter (index 2) is released.
  if (ExprHasName(OriginExpr, "mptcp_close_ssk", C)) {
    RelParams.push_back(2);
    return true;
  }

  // Extendable: add other known "close/free" APIs as needed.

  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> RelParams;
  if (!functionKnownToRelease(Call, RelParams, C))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned Idx : RelParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    // Get the memory region corresponding to the argument's value.
    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;

    // Always normalize to base region.
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    if (!State->contains<ReleasedRegions>(MR)) {
      State = State->add<ReleasedRegions>(MR);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  // Normalize to base region to match what we store.
  const MemRegion *BaseReg = MR->getBaseRegion();
  if (!BaseReg)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<ReleasedRegions>(BaseReg))
    return;

  // The load reads from an object that has been released/closed.
  reportUAF(S, C);
}

void SAGenTestChecker::reportUAF(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use-after-close: reading released object", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects reads from objects after close/free (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
