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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(FreedPtrRegions, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(ReportedRegions, const MemRegion *)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::Location,
        check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-free after release-like call", "Memory Error")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helper: identify release-like calls and which params may be freed.
      bool isReleaseLike(const CallEvent &Call,
                         llvm::SmallVectorImpl<unsigned> &FreedParams,
                         CheckerContext &C) const;

      // Helper: get pointee base MemRegion from a call argument index.
      const MemRegion *getArgPointeeBaseRegion(const CallEvent &Call, unsigned Idx) const;

      // Helper: extract base pointer symbol region from a location being accessed.
      const MemRegion *getBaseRegionFromLoc(SVal Loc) const;

      void reportUAF(const Stmt *Trigger, CheckerContext &C,
                     StringRef Msg, const MemRegion *BaseReg) const;
};

bool SAGenTestChecker::isReleaseLike(const CallEvent &Call,
                                     llvm::SmallVectorImpl<unsigned> &FreedParams,
                                     CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // The target pattern focuses on mptcp_close_ssk(..., ..., subflow)
  if (ExprHasName(Origin, "mptcp_close_ssk", C)) {
    // third argument (0-based index 2) is the subflow that may be freed
    FreedParams.push_back(2);
    return true;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getArgPointeeBaseRegion(const CallEvent &Call, unsigned Idx) const {
  if (Idx >= Call.getNumArgs())
    return nullptr;

  SVal ArgV = Call.getArgSVal(Idx);
  const MemRegion *R = ArgV.getAsRegion();
  if (!R)
    return nullptr;

  const MemRegion *Base = R->getBaseRegion();
  return Base;
}

const MemRegion *SAGenTestChecker::getBaseRegionFromLoc(SVal Loc) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return nullptr;
  return R->getBaseRegion();
}

void SAGenTestChecker::reportUAF(const Stmt *Trigger, CheckerContext &C,
                                 StringRef Msg, const MemRegion *BaseReg) const {
  if (!BaseReg)
    return;

  ProgramStateRef State = C.getState();
  // Avoid duplicate reports for the same region along a path.
  if (State->contains<ReportedRegions>(BaseReg))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, Msg, N);
  if (Trigger)
    R->addRange(Trigger->getSourceRange());
  C.emitReport(std::move(R));

  // Mark as reported in this path.
  State = State->add<ReportedRegions>(BaseReg);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  llvm::SmallVector<unsigned, 4> FreedParams;
  if (!isReleaseLike(Call, FreedParams, C))
    return;

  for (unsigned Idx : FreedParams) {
    const MemRegion *Base = getArgPointeeBaseRegion(Call, Idx);
    if (!Base)
      continue;

    State = State->add<FreedPtrRegions>(Base);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *Base = getBaseRegionFromLoc(Loc);
  if (!Base)
    return;

  if (State->contains<FreedPtrRegions>(Base)) {
    reportUAF(S, C, "Use-after-free: pointer dereferenced after release-like call (e.g., mptcp_close_ssk)", Base);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // If the function is known to dereference certain parameters,
  // passing a freed pointer is a UAF.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const MemRegion *Base = getArgPointeeBaseRegion(Call, Idx);
    if (!Base)
      continue;

    if (State->contains<FreedPtrRegions>(Base)) {
      reportUAF(Call.getOriginExpr(), C,
                "Use-after-free: freed pointer passed to a function that dereferences it",
                Base);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free by dereferencing a pointer after a release-like call (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
