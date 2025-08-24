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

using namespace clang;
using namespace ento;
using namespace taint;

// Program states: track the lifecycle of "req" objects.
REGISTER_MAP_WITH_PROGRAMSTATE(ReqInitSeenMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(ReqAcquiredMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        check::BeginFunction,
        check::PostCall,
        check::PreCall,
        check::PreStmt<ReturnStmt>,
        check::EndFunction> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
                                     "Missing hwrm_req_drop on error path",
                                     "Resource Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helper: match callee name using source text, fallback to identifier if needed.
  static bool isCallee(const CallEvent &Call, StringRef Name, CheckerContext &C);

  // Helper: extract the MemRegion of the 'req' argument at given index.
  static const MemRegion* getReqRegion(const CallEvent &Call, unsigned Index, CheckerContext &C);

  // Report a missing-drop issue at the given statement.
  void reportMissingDrop(const Stmt *S, CheckerContext &C) const;
};

// Helper implementations

bool SAGenTestChecker::isCallee(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (Origin && ExprHasName(Origin, Name, C))
    return true;
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  return false;
}

const MemRegion* SAGenTestChecker::getReqRegion(const CallEvent &Call, unsigned Index, CheckerContext &C) {
  if (Index >= Call.getNumArgs())
    return nullptr;
  const Expr *ArgE = Call.getArgExpr(Index);
  if (!ArgE)
    return nullptr;
  const MemRegion *R = getMemRegionFromExpr(ArgE, C);
  if (!R)
    return nullptr;
  R = R->getBaseRegion();
  return R;
}

void SAGenTestChecker::reportMissingDrop(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Request not released: missing hwrm_req_drop() before return", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// Callbacks

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Clear maps at function entry to avoid cross-function contamination.
  State = State->remove<ReqInitSeenMap>();
  State = State->remove<ReqAcquiredMap>();
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Mark that init has been seen for this req.
  if (isCallee(Call, "hwrm_req_init", C)) {
    const MemRegion *R = getReqRegion(Call, 1, C);
    if (!R)
      return;
    State = State->set<ReqInitSeenMap>(R, true);
    C.addTransition(State);
    return;
  }

  // On drop, clear any acquired/init state for this req.
  if (isCallee(Call, "hwrm_req_drop", C)) {
    const MemRegion *R = getReqRegion(Call, 1, C);
    if (!R)
      return;
    State = State->remove<ReqAcquiredMap>(R);
    State = State->remove<ReqInitSeenMap>(R);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Treat replace as the acquisition point (we've passed successful init).
  if (isCallee(Call, "hwrm_req_replace", C)) {
    const MemRegion *R = getReqRegion(Call, 1, C);
    if (!R)
      return;

    const bool *InitSeen = State->get<ReqInitSeenMap>(R);
    if (InitSeen && *InitSeen) {
      State = State->set<ReqAcquiredMap>(R, true);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // If any req is marked acquired (replace seen, no drop yet), warn.
  auto M = State->get<ReqAcquiredMap>();
  if (!M.isEmpty()) {
    reportMissingDrop(RS, C);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  auto M = State->get<ReqAcquiredMap>();
  if (!M.isEmpty()) {
    // Function end without proper drop.
    reportMissingDrop(RS, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect missing hwrm_req_drop() on error paths after hwrm_req_replace()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
