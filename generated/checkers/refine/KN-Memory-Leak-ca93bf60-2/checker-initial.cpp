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

using namespace clang;
using namespace ento;
using namespace taint;

// Track temporary buffers that must be freed with kfree().
REGISTER_MAP_WITH_PROGRAMSTATE(TempBufMap, const MemRegion*, const Stmt*)
// Track that a devm_krealloc has been seen after allocating a temp buffer.
// This helps avoid reporting early error-returns unrelated to reallocation.
REGISTER_MAP_WITH_PROGRAMSTATE(ReallocSeenMap, const MemRegion*, const Stmt*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::PreStmt<ReturnStmt>
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Leaked temporary buffer from nvmem_cell_read", "Memory Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

   private:

      // Helpers
      static bool isTempAllocReturningKmem(const CallEvent &Call, CheckerContext &C);
      static bool isFreeLike(const CallEvent &Call, CheckerContext &C);
      static bool isDevmKrealloc(const CallEvent &Call, CheckerContext &C);

      static const MemRegion* getReturnedRegion(const CallEvent &Call);
      static const MemRegion* getFreedRegion(const CallEvent &Call, CheckerContext &C);

      void reportLeak(const MemRegion *R, const Stmt *AllocSite, const Stmt *Sink, CheckerContext &C) const;
};

// Returns true for functions that return a kmem buffer requiring kfree().
// Minimal set to match the target bug: nvmem_cell_read.
bool SAGenTestChecker::isTempAllocReturningKmem(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "nvmem_cell_read", C);
}

bool SAGenTestChecker::isFreeLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "kfree", C) || ExprHasName(Origin, "kvfree", C);
}

bool SAGenTestChecker::isDevmKrealloc(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "devm_krealloc", C);
}

const MemRegion* SAGenTestChecker::getReturnedRegion(const CallEvent &Call) {
  const MemRegion *MR = Call.getReturnValue().getAsRegion();
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::getFreedRegion(const CallEvent &Call, CheckerContext &C) {
  if (Call.getNumArgs() == 0)
    return nullptr;
  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Track temporary allocations that must be freed.
  if (isTempAllocReturningKmem(Call, C)) {
    const MemRegion *R = getReturnedRegion(Call);
    if (R) {
      State = State->set<TempBufMap>(R, Call.getOriginExpr());
      Changed = true;
    }
  }

  // When a devm_krealloc is seen, remember that it happened after any outstanding temp buffers.
  if (isDevmKrealloc(Call, C)) {
    auto Map = State->get<TempBufMap>();
    if (!Map.isEmpty()) {
      for (auto It = Map.begin(), E = Map.end(); It != E; ++It) {
        const MemRegion *R = It->first;
        State = State->set<ReallocSeenMap>(R, Call.getOriginExpr());
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeLike(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *FR = getFreedRegion(Call, C);
  if (!FR)
    return;

  const Stmt **Val = State->get<TempBufMap>(FR);
  if (!Val)
    return;

  State = State->remove<TempBufMap>(FR);
  State = State->remove<ReallocSeenMap>(FR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If no outstanding temp buffers, nothing to do.
  auto Map = State->get<TempBufMap>();
  if (Map.isEmpty())
    return;

  // Optional suppression: if returning the tracked pointer itself, skip.
  if (const Expr *RetE = RS->getRetValue()) {
    SVal RetV = State->getSVal(RetE, C.getLocationContext());
    if (const MemRegion *RetR = RetV.getAsRegion()) {
      RetR = RetR->getBaseRegion();
      if (RetR) {
        const Stmt **AllocSite = State->get<TempBufMap>(RetR);
        if (AllocSite) {
          // Assume ownership transfer, do not report.
          return;
        }
      }
    }
  }

  // Report for the first outstanding temp buffer that is after a devm_krealloc seen on this path.
  for (auto It = Map.begin(), E = Map.end(); It != E; ++It) {
    const MemRegion *R = It->first;
    const Stmt *AllocSite = It->second;

    const Stmt **AfterRealloc = State->get<ReallocSeenMap>(R);
    if (!AfterRealloc)
      continue; // Only report when a devm_krealloc has been seen after allocation.

    reportLeak(R, AllocSite, RS, C);
    return; // Report one per return site.
  }
}

void SAGenTestChecker::reportLeak(const MemRegion *R, const Stmt *AllocSite, const Stmt *Sink, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Temporary buffer not freed on early return", N);
  if (Sink)
    Report->addRange(Sink->getSourceRange());

  if (AllocSite) {
    const SourceManager &SM = C.getSourceManager();
    const LocationContext *LCtx = C.getLocationContext();
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(AllocSite, SM, LCtx);
    Report->addNote("allocated here", Loc);
  }

  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing kfree of buffers returned by nvmem_cell_read when returning early after devm_krealloc failure",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
