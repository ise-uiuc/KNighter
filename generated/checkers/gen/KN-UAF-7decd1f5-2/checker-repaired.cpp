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
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track regions of objects that have been closed/teardown'd and must not be used.
REGISTER_SET_WITH_PROGRAMSTATE(FreedRegionSet, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<
                           check::PostCall,
                           check::PreCall,
                           check::Location> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Use-after-close", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Known teardown/free functions that invalidate/destroy their pointer params.
  bool functionKnownToFree(const CallEvent &Call,
                           llvm::SmallVectorImpl<unsigned> &FreedParams,
                           CheckerContext &C) const;

  void reportUseAfterClose(const Stmt *S, CheckerContext &C,
                           StringRef Msg) const;
};

bool SAGenTestChecker::functionKnownToFree(const CallEvent &Call,
                                           llvm::SmallVectorImpl<unsigned> &FreedParams,
                                           CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // mptcp_close_ssk(sk, ssk, subflow) - the 3rd arg (index 2) may be released.
  if (ExprHasName(OriginExpr, "mptcp_close_ssk", C)) {
    FreedParams.push_back(2);
    return true;
  }

  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  llvm::SmallVector<unsigned, 2> FreedParams;
  if (!functionKnownToFree(Call, FreedParams, C))
    return;

  bool Changed = false;
  for (unsigned Idx : FreedParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *ObjR = getMemRegionFromExpr(ArgE, C);
    if (!ObjR)
      continue;

    ObjR = ObjR->getBaseRegion();
    if (!ObjR)
      continue;

    if (!State->contains<FreedRegionSet>(ObjR)) {
      State = State->add<FreedRegionSet>(ObjR);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<FreedRegionSet>(R)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Rpt = std::make_unique<PathSensitiveBugReport>(
        *BT, "Reading object after teardown/close.", N);
    if (S)
      Rpt->addRange(S->getSourceRange());
    C.emitReport(std::move(Rpt));
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
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

    const MemRegion *ObjR = getMemRegionFromExpr(ArgE, C);
    if (!ObjR)
      continue;

    ObjR = ObjR->getBaseRegion();
    if (!ObjR)
      continue;

    if (State->contains<FreedRegionSet>(ObjR)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Rpt = std::make_unique<PathSensitiveBugReport>(
          *BT, "Passing closed object to a function that dereferences it.", N);
      Rpt->addRange(ArgE->getSourceRange());
      C.emitReport(std::move(Rpt));
      // Do not early return; there may be multiple bad args.
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use after close: accessing objects after teardown (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
