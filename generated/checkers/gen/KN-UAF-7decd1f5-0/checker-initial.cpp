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
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

//================ Program state customizations ================

// Tracks base regions (of pointed objects) that have been released,
// mapped to the name of the releasing function (string literal).
REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedMap, const MemRegion*, const char*)

// Tracks simple pointer alias relations (one-hop, symmetric).
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

// Helper table for functions that may release/free certain pointer params.
struct KnownReleaseFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params; // 0-based indices of params that are released/freed
};

static const KnownReleaseFunction ReleaseTable[] = {
  {"kfree", {0}},
  {"kvfree", {0}},
  {"mptcp_close_ssk", {2}}, // third parameter (subflow) is released/teardown
};

// Forward declarations of helpers
static const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C);
static const MemRegion *getBaseFromLoc(SVal Loc);
static bool functionKnownToRelease(const CallEvent &Call,
                                   CheckerContext &C,
                                   llvm::SmallVectorImpl<unsigned> &FreedParams,
                                   const char* &FnNameOut);
static llvm::SmallVector<const MemRegion*, 4>
getAllAliases(ProgramStateRef State, const MemRegion *R);

static ProgramStateRef markReleased(ProgramStateRef State,
                                    const MemRegion *R,
                                    const char *FnName);

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::Location,
      check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-free", "Memory Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      void reportUAF(const Stmt *S, const char *ByFn, StringRef Detail, CheckerContext &C) const;
};

//================ Helper implementations ================

static const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

static const MemRegion *getBaseFromLoc(SVal Loc) {
  if (const MemRegion *MR = Loc.getAsRegion()) {
    return MR->getBaseRegion();
  }
  return nullptr;
}

static bool functionKnownToRelease(const CallEvent &Call,
                                   CheckerContext &C,
                                   llvm::SmallVectorImpl<unsigned> &FreedParams,
                                   const char* &FnNameOut) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  for (const auto &Entry : ReleaseTable) {
    if (ExprHasName(Origin, Entry.Name, C)) {
      FreedParams.append(Entry.Params.begin(), Entry.Params.end());
      FnNameOut = Entry.Name;
      return true;
    }
  }
  return false;
}

static llvm::SmallVector<const MemRegion*, 4>
getAllAliases(ProgramStateRef State, const MemRegion *R) {
  llvm::SmallVector<const MemRegion*, 4> Res;
  if (!R)
    return Res;
  // Always include itself
  Res.push_back(R);

  // One-hop forward
  if (const MemRegion *Fwd = State->get<PtrAliasMap>(R)) {
    if (Fwd)
      Res.push_back(Fwd->getBaseRegion());
  }
  return Res;
}

static ProgramStateRef markReleased(ProgramStateRef State,
                                    const MemRegion *R,
                                    const char *FnName) {
  if (!R || !FnName)
    return State;

  auto All = getAllAliases(State, R->getBaseRegion());
  for (const MemRegion *AR : All) {
    if (!AR) continue;
    AR = AR->getBaseRegion();
    State = State->set<ReleasedMap>(AR, FnName);
  }
  return State;
}

//================ Checker logic ================

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  llvm::SmallVector<unsigned, 4> FreedParams;
  const char *FnName = nullptr;
  if (!functionKnownToRelease(Call, C, FreedParams, FnName))
    return;

  for (unsigned Idx : FreedParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    const MemRegion *Base = getBaseRegionFromExpr(ArgE, C);
    if (!Base)
      continue;

    State = markReleased(State, Base, FnName);
  }

  if (State)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    const MemRegion *Base = getBaseRegionFromExpr(ArgE, C);
    if (!Base)
      continue;

    const char **ReleasedBy = State->get<ReleasedMap>(Base);
    if (ReleasedBy && *ReleasedBy) {
      // Report UAF at call site: passing a released pointer to a function that dereferences it.
      reportUAF(Call.getOriginExpr(), *ReleasedBy,
                "passing released pointer to a function that dereferences it", C);
      return;
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *Base = getBaseFromLoc(Loc);
  if (!Base)
    return;

  const char **ReleasedBy = State->get<ReleasedMap>(Base);
  if (!ReleasedBy || !*ReleasedBy)
    return;

  // Use-after-free detected on memory access (load/store).
  reportUAF(S, *ReleasedBy, "pointer used after it was released", C);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;

  if (LHSReg == RHSReg)
    return;

  // Record symmetric alias relation (one hop).
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);

  // Propagate released status if any side is already marked released.
  if (const char **ReleasedBy = State->get<ReleasedMap>(LHSReg)) {
    if (ReleasedBy && *ReleasedBy) {
      State = markReleased(State, RHSReg, *ReleasedBy);
    }
  }
  if (const char **ReleasedBy = State->get<ReleasedMap>(RHSReg)) {
    if (ReleasedBy && *ReleasedBy) {
      State = markReleased(State, LHSReg, *ReleasedBy);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportUAF(const Stmt *S, const char *ByFn, StringRef Detail, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "use-after-free: ";
  if (!Detail.empty()) {
    Msg += Detail;
    Msg += "; ";
  }
  Msg += "released by call to ";
  Msg += ByFn;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free when a pointer is used after a function may release it (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
