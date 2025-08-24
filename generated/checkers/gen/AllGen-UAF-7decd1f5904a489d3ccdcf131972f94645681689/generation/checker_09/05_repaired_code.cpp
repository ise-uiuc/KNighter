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
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track symbols of objects that may have been released/freed.
REGISTER_SET_WITH_PROGRAMSTATE(FreedSymSet, SymbolRef)

namespace {

struct KnownFreeFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params; // 0-based indices of pointer params that may be freed
};

static const KnownFreeFunction FreeTable[] = {
    // The target problem: mptcp_close_ssk(..., subflow) can release the subflow.
    {"mptcp_close_ssk", {2}},
    // Optional common free-like helpers to broaden coverage.
    {"kfree", {0}},
    {"kvfree", {0}},
    {"kfree_rcu", {0}},
};

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-free after close/release", "Memory")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool functionKnownToFree(const CallEvent &Call,
                                      llvm::SmallVectorImpl<unsigned> &FreeParams,
                                      CheckerContext &C);

      static SymbolRef getBaseObjectSymbolFromRegion(const MemRegion *R);
      static SymbolRef getPointeeSymbolFromSVal(SVal V);

      void reportUAF(const Stmt *S, StringRef Msg, CheckerContext &C) const;
};

bool SAGenTestChecker::functionKnownToFree(const CallEvent &Call,
                                           llvm::SmallVectorImpl<unsigned> &FreeParams,
                                           CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  for (const auto &Entry : FreeTable) {
    if (ExprHasName(Origin, Entry.Name, C)) {
      FreeParams.append(Entry.Params.begin(), Entry.Params.end());
      return true;
    }
  }
  return false;
}

SymbolRef SAGenTestChecker::getBaseObjectSymbolFromRegion(const MemRegion *R) {
  if (!R)
    return nullptr;

  // Always go through base region.
  R = R->getBaseRegion();
  if (!R)
    return nullptr;

  const MemRegion *SymBase = R->getSymbolicBase();
  if (!SymBase)
    return nullptr;

  if (const auto *SR = dyn_cast<SymbolicRegion>(SymBase))
    return SR->getSymbol();

  return nullptr;
}

SymbolRef SAGenTestChecker::getPointeeSymbolFromSVal(SVal V) {
  if (V.isUnknownOrUndef())
    return nullptr;

  if (const MemRegion *R = V.getAsRegion()) {
    // The value is a region-valued pointer. Extract the symbolic base of the
    // pointed-to object.
    return getBaseObjectSymbolFromRegion(R);
  }

  if (SymbolRef Sym = V.getAsSymbol())
    return Sym;

  // If it's a concrete int (e.g., NULL), or something else, bail out.
  return nullptr;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> FreeParams;
  if (!functionKnownToFree(Call, FreeParams, C))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : FreeParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    SVal ArgV = Call.getArgSVal(Idx);
    SymbolRef PointeeSym = getPointeeSymbolFromSVal(ArgV);
    if (!PointeeSym)
      continue;

    State = State->add<FreedSymSet>(PointeeSym);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only care when we are accessing memory by region (load/store of a field or *ptr).
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  // Always get the base region per suggestion.
  R = R->getBaseRegion();
  if (!R)
    return;

  SymbolRef BaseSym = getBaseObjectSymbolFromRegion(R);
  if (!BaseSym)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<FreedSymSet>(BaseSym)) {
    reportUAF(S, "Use-after-free: object accessed after a call that may free it", C);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // If a freed object is passed to a function known to dereference it, report.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    SVal ArgV = Call.getArgSVal(Idx);
    SymbolRef PointeeSym = getPointeeSymbolFromSVal(ArgV);
    if (!PointeeSym)
      continue;

    if (State->contains<FreedSymSet>(PointeeSym)) {
      // Passing a freed object to a function that dereferences it.
      const Stmt *S = Call.getOriginExpr();
      reportUAF(S, "Use-after-free: passing freed object to a function that dereferences it", C);
      // No need to continue reporting multiple times for this call.
      return;
    }
  }
}

void SAGenTestChecker::reportUAF(const Stmt *S, StringRef Msg, CheckerContext &C) const {
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
      "Detects use-after-free by accessing an object after a call that may free it (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
