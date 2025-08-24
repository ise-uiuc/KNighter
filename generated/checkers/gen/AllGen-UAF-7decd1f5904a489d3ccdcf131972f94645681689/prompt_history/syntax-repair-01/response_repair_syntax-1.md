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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include <string>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(FreedRegions, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(FreedByFuncMap, const MemRegion*, const char*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::Location
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-free", "Memory Error")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Known free-like functions table and matcher
      bool functionKnownToFree(const CallEvent &Call,
                               llvm::SmallVectorImpl<unsigned> &FreedParams,
                               const char* &Name,
                               CheckerContext &C) const;

      // Helpers
      const MemRegion *getBase(const MemRegion *R) const {
        if (!R) return nullptr;
        return R->getBaseRegion();
      }

      const MemRegion *getPointeeBaseRegionFromArg(const Expr *E, CheckerContext &C) const {
        if (!E)
          return nullptr;
        const MemRegion *R = C.getSVal(E).getAsRegion();
        if (!R)
          return nullptr;
        // Normalize to the object's base region (owning object)
        return getBase(R);
      }

      ProgramStateRef markFreed(ProgramStateRef State, const MemRegion *R, const char *FnName) const {
        if (!R) return State;
        const MemRegion *Base = getBase(R);
        if (!Base) return State;
        State = State->add<FreedRegions>(Base);
        State = State->set<FreedByFuncMap>(Base, FnName);
        return State;
      }

      bool isFreed(const MemRegion *R, ProgramStateRef State) const {
        if (!R) return false;
        const MemRegion *Base = getBase(R);
        if (!Base) return false;
        return State->contains<FreedRegions>(Base);
      }
};

// Known free-like functions that free/schedule-free of their pointer params.
bool SAGenTestChecker::functionKnownToFree(const CallEvent &Call,
                                           llvm::SmallVectorImpl<unsigned> &FreedParams,
                                           const char* &Name,
                                           CheckerContext &C) const {
  struct FreeEntry {
    const char *Name;
    unsigned Params[3];
    unsigned Count;
  };

  static const FreeEntry Table[] = {
    {"kfree",           {0}, 1},
    {"kvfree",          {0}, 1},
    {"kvfree_rcu",      {0}, 1},
    // Target-specific: frees/schedules freeing of the subflow context
    {"mptcp_close_ssk", {2}, 1}
  };

  const Expr *Orig = Call.getOriginExpr();
  const IdentifierInfo *ID = Call.getCalleeIdentifier();

  for (const auto &E : Table) {
    bool match = false;
    if (Orig && ExprHasName(Orig, E.Name, C)) {
      match = true;
    } else if (ID && ID->getName() == E.Name) {
      match = true;
    }
    if (!match)
      continue;

    FreedParams.clear();
    for (unsigned i = 0; i < E.Count; ++i)
      FreedParams.push_back(E.Params[i]);
    Name = E.Name;
    return true;
  }

  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> FreedParams;
  const char *FnName = nullptr;

  if (!functionKnownToFree(Call, FreedParams, FnName, C))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned Idx : FreedParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    const MemRegion *PointeeBase = getPointeeBaseRegionFromArg(ArgE, C);
    if (!PointeeBase)
      continue;

    State = markFreed(State, PointeeBase, FnName);
    Changed = true;
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad || !S)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  if (!isFreed(R, State))
    return;

  // Prepare a concise message
  const MemRegion *Base = R->getBaseRegion();
  const char *const *FnNamePtr = State->get<FreedByFuncMap>(Base);
  std::string Msg;
  if (FnNamePtr && *FnNamePtr) {
    Msg = "Use-after-free: read after call to '";
    Msg += *FnNamePtr;
    Msg += "'";
  } else {
    Msg = "Use-after-free: read from freed object";
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects reads from objects after free-like calls (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
