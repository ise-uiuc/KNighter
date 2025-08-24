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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(DevLenKindMap, const MemRegion*, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(DevLenCheckedMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(DevLenOriginSite, const MemRegion*, const Stmt*)

namespace {

enum DevLenKind : unsigned {
  RSS_KEY_SIZE = 1
};

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::Bind,
                                        check::BranchCondition,
                                        check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unvalidated device length used for RSS key", "API Misuse")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:

      bool isInVirtnetProbe(CheckerContext &C) const;
      void markAllKindChecked(ProgramStateRef &State, unsigned Kind) const;
};

bool SAGenTestChecker::isInVirtnetProbe(CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;
  const Decl *D = LCtx->getDecl();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;
  // Limit scope to virtnet_probe to reduce false positives
  return FD->getName().equals("virtnet_probe");
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S || !isInVirtnetProbe(C))
    return;

  // Look for binding from a call expression, specifically virtio_cread8(..., rss_max_key_size)
  const CallExpr *CE = findSpecificTypeInChildren<const CallExpr>(S);
  if (!CE)
    return;

  // Verify function and field names by source text
  if (!ExprHasName(CE, "virtio_cread8", C))
    return;
  if (!ExprHasName(CE, "rss_max_key_size", C))
    return;

  // Get the destination region being assigned/bound
  const MemRegion *DstReg = Loc.getAsRegion();
  if (!DstReg)
    return;

  DstReg = DstReg->getBaseRegion();
  if (!DstReg)
    return;

  ProgramStateRef State = C.getState();
  // Track this device length as RSS_KEY_SIZE and initially unchecked
  State = State->set<DevLenKindMap>(DstReg, (unsigned)RSS_KEY_SIZE);
  State = State->set<DevLenCheckedMap>(DstReg, false);
  State = State->set<DevLenOriginSite>(DstReg, S);

  C.addTransition(State);
}

void SAGenTestChecker::markAllKindChecked(ProgramStateRef &State, unsigned Kind) const {
  auto Map = State->get<DevLenKindMap>();
  for (auto It = Map.begin(), E = Map.end(); It != E; ++It) {
    const MemRegion *MR = It->first;
    unsigned K = It->second;
    if (K == Kind) {
      // Only set to true if it was tracked before
      const bool *Checked = State->get<DevLenCheckedMap>(MR);
      if (!Checked || !*Checked) {
        State = State->set<DevLenCheckedMap>(MR, true);
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!isInVirtnetProbe(C))
    return;

  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  // Consider the length "validated" if a condition mentions both:
  // - rss_key_size
  // - VIRTIO_NET_RSS_MAX_KEY_SIZE
  bool HasLen = ExprHasName(CondE, "rss_key_size", C);
  bool HasMax = ExprHasName(CondE, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C);
  if (!HasLen || !HasMax)
    return;

  ProgramStateRef State = C.getState();
  markAllKindChecked(State, (unsigned)RSS_KEY_SIZE);
  C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  auto KindMap = State->get<DevLenKindMap>();

  for (auto It = KindMap.begin(), E = KindMap.end(); It != E; ++It) {
    const MemRegion *MR = It->first;
    unsigned Kind = It->second;

    if (Kind != (unsigned)RSS_KEY_SIZE)
      continue;

    const bool *Checked = State->get<DevLenCheckedMap>(MR);
    if (Checked && *Checked)
      continue;

    // Not checked: report a bug.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      continue;

    const Stmt *Origin = State->get<DevLenOriginSite>(MR);
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Device length (rss_max_key_size) not validated against VIRTIO_NET_RSS_MAX_KEY_SIZE.", N);

    if (Origin)
      R->addRange(Origin->getSourceRange());

    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects using device-provided rss_max_key_size without validating against VIRTIO_NET_RSS_MAX_KEY_SIZE",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
