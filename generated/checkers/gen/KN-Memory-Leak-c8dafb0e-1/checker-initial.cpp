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

// Track req objects initialized by hwrm_req_init and not yet dropped.
REGISTER_SET_WITH_PROGRAMSTATE(InitReqSet, const MemRegion*)
// Track req objects that, after at least one post-init API call, must be dropped on all exits.
REGISTER_SET_WITH_PROGRAMSTATE(MustDropSet, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreStmt<ReturnStmt>,
        check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "HWRM request leak", "Resource Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:
      bool callIsNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const;
      const MemRegion *getReqRegionFromCallArg1(const CallEvent &Call, CheckerContext &C) const;
      void reportMissingDrop(const Stmt *ExitStmt, CheckerContext &C) const;
};

bool SAGenTestChecker::callIsNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

const MemRegion *SAGenTestChecker::getReqRegionFromCallArg1(const CallEvent &Call, CheckerContext &C) const {
  if (Call.getNumArgs() <= 1)
    return nullptr;
  const Expr *ArgE = Call.getArgExpr(1);
  if (!ArgE)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Match APIs using expression text for robustness.
  bool IsInit = callIsNamed(Call, C, "hwrm_req_init");
  bool IsDrop = callIsNamed(Call, C, "hwrm_req_drop") || callIsNamed(Call, C, "bnxt_req_drop");
  bool IsPostInit =
      callIsNamed(Call, C, "hwrm_req_replace") ||
      callIsNamed(Call, C, "hwrm_req_timeout") ||
      callIsNamed(Call, C, "hwrm_req_hold") ||
      callIsNamed(Call, C, "hwrm_req_send");

  if (!IsInit && !IsDrop && !IsPostInit)
    return;

  const MemRegion *ReqReg = getReqRegionFromCallArg1(Call, C);
  if (!ReqReg)
    return;

  if (IsInit) {
    // Record that 'req' has been initialized.
    if (!State->contains<InitReqSet>(ReqReg)) {
      State = State->add<InitReqSet>(ReqReg);
    }
    // Do not add to MustDropSet yet; require a post-init call first.
    C.addTransition(State);
    return;
  }

  if (IsPostInit) {
    // After a post-init call, this req must be dropped on all exit paths.
    if (State->contains<InitReqSet>(ReqReg)) {
      if (!State->contains<MustDropSet>(ReqReg)) {
        State = State->add<MustDropSet>(ReqReg);
        C.addTransition(State);
      }
    }
    return;
  }

  if (IsDrop) {
    // Drop resets both Init and MustDrop tracking for this req.
    if (State->contains<InitReqSet>(ReqReg) || State->contains<MustDropSet>(ReqReg)) {
      State = State->remove<InitReqSet>(ReqReg);
      State = State->remove<MustDropSet>(ReqReg);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::reportMissingDrop(const Stmt *ExitStmt, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const auto *S = State->get<MustDropSet>();
  if (!S || S->isEmpty())
    return;

  // Report once per outstanding req region (usually one).
  for (const MemRegion *ReqReg : *S) {
    (void)ReqReg; // not used directly, kept for potential future notes.

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      continue;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Missing hwrm_req_drop() before return after HWRM request setup", N);

    if (ExitStmt)
      R->addRange(ExitStmt->getSourceRange());

    C.emitReport(std::move(R));
  }
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  reportMissingDrop(RS, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Avoid duplicate reports for explicit returns; we already reported in checkPreStmt.
  if (RS)
    return;

  // Report for implicit exit paths (e.g., reaching end of function).
  reportMissingDrop(/*ExitStmt=*/nullptr, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect missing hwrm_req_drop() on early returns after HWRM request setup",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
