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
#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track variables/fields that hold rss_max_key_size and need validation.
REGISTER_MAP_WITH_PROGRAMSTATE(RssKeySizeMap, const MemRegion *, unsigned)

namespace {

enum RssKeyCheckState : unsigned {
  NeedsCheck = 0,
  Checked = 1
};

class SAGenTestChecker
  : public Checker<
      check::PostCall,        // track virtio_cread8(... rss_max_key_size)
      check::PreCall,         // detect uses as length in memcpy/memmove/memset/sg_init_one
      check::BranchCondition  // mark checked when compared against VIRTIO_NET_RSS_MAX_KEY_SIZE
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(std::make_unique<BugType>(this, "Unchecked device-reported RSS key length", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      bool isVirtioCread8RssKeySize(const CallEvent &Call, CheckerContext &C) const;
      const MemRegion *getAssignedRegionForCallResult(const CallEvent &Call, CheckerContext &C) const;
      ProgramStateRef markRegionCheckedIfComparedToMax(const Stmt *Cond, CheckerContext &C, ProgramStateRef State) const;
      bool isKnownLengthUse(const CallEvent &Call, CheckerContext &C, unsigned &LenParamIdx) const;
      const MemRegion *argExprRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      void reportUncheckedLengthUse(const Stmt *UseSite, CheckerContext &C, const MemRegion *R) const;
};

// Determine if this call is virtio_cread8(...) where an argument mentions rss_max_key_size.
bool SAGenTestChecker::isVirtioCread8RssKeySize(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Use source-text matching for callee name as suggested.
  if (!ExprHasName(Origin, "virtio_cread8", C))
    return false;

  // Look for "rss_max_key_size" in any argument's source.
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    if (const Expr *AE = Call.getArgExpr(i)) {
      if (ExprHasName(AE, "rss_max_key_size", C))
        return true;
    }
  }
  return false;
}

// From the virtio_cread8(...) call, find the assignment LHS region that receives the result.
const MemRegion *SAGenTestChecker::getAssignedRegionForCallResult(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return nullptr;
  const auto *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return nullptr;

  // Ascend to parent BinaryOperator '='
  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(CE, C);
  if (!BO || !BO->isAssignmentOp())
    return nullptr;

  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(LHS, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

// If a branch condition compares the tracked variable to VIRTIO_NET_RSS_MAX_KEY_SIZE, mark it checked.
ProgramStateRef SAGenTestChecker::markRegionCheckedIfComparedToMax(const Stmt *Cond, CheckerContext &C, ProgramStateRef State) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Cond);
  if (!CondE)
    return State;

  // Ensure the macro appears in the condition.
  if (!ExprHasName(CondE, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C))
    return State;

  // Try to find a MemberExpr (e.g., vi->rss_key_size) first.
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Cond);
  const Expr *TargetExpr = nullptr;
  if (ME) {
    TargetExpr = ME;
  } else {
    // Fallback: find a DeclRefExpr (e.g., local variable holding the size)
    const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Cond);
    if (DRE)
      TargetExpr = DRE;
  }

  if (!TargetExpr)
    return State;

  const MemRegion *MR = getMemRegionFromExpr(TargetExpr, C);
  if (!MR)
    return State;
  MR = MR->getBaseRegion();

  const unsigned *Val = State->get<RssKeySizeMap>(MR);
  if (Val && *Val == NeedsCheck) {
    State = State->set<RssKeySizeMap>(MR, Checked);
  }
  return State;
}

// Recognize common functions where a length parameter is used.
bool SAGenTestChecker::isKnownLengthUse(const CallEvent &Call, CheckerContext &C, unsigned &LenParamIdx) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // memcpy/memmove/memset have length as the 3rd argument (index 2).
  if (ExprHasName(Origin, "memcpy", C) ||
      ExprHasName(Origin, "memmove", C) ||
      ExprHasName(Origin, "memset", C)) {
    LenParamIdx = 2;
    return true;
  }

  // sg_init_one(sg, buf, buflen)
  if (ExprHasName(Origin, "sg_init_one", C)) {
    LenParamIdx = 2;
    return true;
  }

  return false;
}

// Obtain the MemRegion corresponding to an argument expression (try MemberExpr then DeclRefExpr).
const MemRegion *SAGenTestChecker::argExprRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  if (Idx >= Call.getNumArgs())
    return nullptr;

  const Expr *ArgE = Call.getArgExpr(Idx);
  if (!ArgE)
    return nullptr;

  // Prefer a MemberExpr inside the argument (typical for vi->rss_key_size).
  if (const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(ArgE)) {
    const MemRegion *MR = getMemRegionFromExpr(ME, C);
    if (MR)
      return MR->getBaseRegion();
  }

  if (const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(ArgE)) {
    const MemRegion *MR = getMemRegionFromExpr(DRE, C);
    if (MR)
      return MR->getBaseRegion();
  }

  // As a last resort, try the raw expression (may fail if rvalue).
  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (MR)
    return MR->getBaseRegion();

  return nullptr;
}

void SAGenTestChecker::reportUncheckedLengthUse(const Stmt *UseSite, CheckerContext &C, const MemRegion *R) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Device-reported RSS key length is used without validating against VIRTIO_NET_RSS_MAX_KEY_SIZE",
      N);
  if (UseSite)
    Rpt->addRange(UseSite->getSourceRange());
  C.emitReport(std::move(Rpt));
}

// Post-call: track assignments from virtio_cread8(... rss_max_key_size)
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isVirtioCread8RssKeySize(Call, C))
    return;

  const MemRegion *Assigned = getAssignedRegionForCallResult(Call, C);
  if (!Assigned)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<RssKeySizeMap>(Assigned, NeedsCheck);
  C.addTransition(State);
}

// When encountering branch conditions, mark the length as checked if compared to macro.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = markRegionCheckedIfComparedToMax(Condition, C, State);
  C.addTransition(State);
}

// Pre-call: detect using the unvalidated length as the size argument in known functions.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned LenIdx = 0;
  if (!isKnownLengthUse(Call, C, LenIdx))
    return;

  const MemRegion *LenReg = argExprRegion(Call, LenIdx, C);
  if (!LenReg)
    return;

  ProgramStateRef State = C.getState();
  const unsigned *Val = State->get<RssKeySizeMap>(LenReg);
  if (!Val)
    return;

  if (*Val == NeedsCheck) {
    // Found a use of the length before validating against the max.
    reportUncheckedLengthUse(Call.getOriginExpr(), C, LenReg);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects using device-reported RSS key length without checking against VIRTIO_NET_RSS_MAX_KEY_SIZE",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
