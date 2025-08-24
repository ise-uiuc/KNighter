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
#include "clang/Lex/Lexer.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
// Tracks “software SQ object” instances (the base pointer/struct region for sq) that have had a successful low-level create call observed.
REGISTER_MAP_WITH_PROGRAMSTATE(SQCreated, const MemRegion*, bool)
// Maps the field region of sq->sqn to the base MemRegion of sq (kept for completeness, though we primarily compute base directly).
REGISTER_MAP_WITH_PROGRAMSTATE(SQFieldToBase, const MemRegion*, const MemRegion*)
// Maps the symbolic return value from hws_send_ring_set_sq_rdy() to the owning sq base region.
REGISTER_MAP_WITH_PROGRAMSTATE(RetSymToSQBase, SymbolRef, const MemRegion*)
// Marks that we are currently in the error branch that corresponds to “set_sq_rdy() failed” for a specific sq.
REGISTER_MAP_WITH_PROGRAMSTATE(SQErrBranchActive, const MemRegion*, bool)

namespace {

static bool callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

static const MemberExpr *getMemberExprFromArg(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  return findSpecificTypeInChildren<MemberExpr>(E);
}

// Compute the base region that represents the SQ object being pointed to,
// by taking the FieldRegion of 'sq->sqn' MemberExpr and getting its base.
static const MemRegion *getSQBaseRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C) {
  if (!ME)
    return nullptr;

  // Important: do not IgnoreImplicit() before getMemRegionFromExpr per guidance.
  const MemRegion *FieldReg = getMemRegionFromExpr(ME, C);
  if (!FieldReg)
    return nullptr;

  const MemRegion *BaseReg = FieldReg->getBaseRegion();
  return BaseReg;
}

// Extract base region of SQ from a function argument that is the 'sq' pointer.
// We want the pointee's base region (the software SQ object), so we fetch the
// region value of the expression and take its base.
static const MemRegion *getSQBaseRegionFromPointerArg(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  // Do not IgnoreImplicit() here.
  const MemRegion *Reg = getMemRegionFromExpr(E, C);
  if (!Reg)
    return nullptr;

  // Always normalize to the base region, per guidance.
  return Reg->getBaseRegion();
}

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::BranchCondition
    > {

   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Wrong cleanup after SQ set_rdy failure", "Resource Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers recognizing specific functions
  static bool isCreateSQ(const CallEvent &Call, CheckerContext &C) {
    return callHasName(Call, C, "mlx5_core_create_sq");
  }
  static bool isSetSQReady(const CallEvent &Call, CheckerContext &C) {
    return callHasName(Call, C, "hws_send_ring_set_sq_rdy");
  }
  static bool isCloseSQ(const CallEvent &Call, CheckerContext &C) {
    return callHasName(Call, C, "hws_send_ring_close_sq");
  }
  static bool isDestroySQ(const CallEvent &Call, CheckerContext &C) {
    return callHasName(Call, C, "mlx5_core_destroy_sq");
  }

  void reportWrongCleanup(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track mlx5_core_create_sq(mdev, in, inlen, &sq->sqn)
  if (isCreateSQ(Call, C)) {
    // 4th argument (index 3) is expected to be &sq->sqn
    if (Call.getNumArgs() > 3) {
      const Expr *Arg3 = Call.getArgExpr(3);
      const MemberExpr *ME = getMemberExprFromArg(Arg3, C);
      if (ME) {
        const MemRegion *BaseReg = getSQBaseRegionFromMemberExpr(ME, C);
        if (BaseReg) {
          // Optionally keep a trivial field->base map for completeness
          const MemRegion *FieldReg = getMemRegionFromExpr(ME, C);
          if (FieldReg) {
            // Per guidance, use base region normalization for keys as well
            State = State->set<SQFieldToBase>(FieldReg->getBaseRegion(), BaseReg);
          }
          State = State->set<SQCreated>(BaseReg, true);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // Track hws_send_ring_set_sq_rdy(mdev, sq->sqn)
  if (isSetSQReady(Call, C)) {
    if (Call.getNumArgs() > 1) {
      const Expr *Arg1 = Call.getArgExpr(1);
      const MemberExpr *ME = getMemberExprFromArg(Arg1, C);
      if (ME) {
        const MemRegion *BaseReg = getSQBaseRegionFromMemberExpr(ME, C);
        if (BaseReg) {
          // Map the return symbol to the SQ base region
          SVal Ret = Call.getReturnValue();
          if (SymbolRef RetSym = Ret.getAsSymbol()) {
            State = State->set<RetSymToSQBase>(RetSym, BaseReg);
            // Clean any stale error-branch marker for fresh call context.
            State = State->remove<SQErrBranchActive>(BaseReg);
            C.addTransition(State);
            return;
          }
        } else {
          // As a fallback, try mapping via field->base if we had it
          const MemRegion *FieldReg = getMemRegionFromExpr(ME, C);
          if (FieldReg) {
            const MemRegion * const *MappedBasePtr =
                State->get<SQFieldToBase>(FieldReg->getBaseRegion());
            if (MappedBasePtr) {
              const MemRegion *MappedBase = *MappedBasePtr;
              if (SymbolRef RetSym = Call.getReturnValue().getAsSymbol()) {
                State = State->set<RetSymToSQBase>(RetSym, MappedBase);
                State = State->remove<SQErrBranchActive>(MappedBase);
                C.addTransition(State);
                return;
              }
            }
          }
        }
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  SVal CondV = State->getSVal(CondE, C.getLocationContext());

  // We only care about conditions like "if (err)" that are backed by a symbol.
  if (SymbolRef Sym = CondV.getAsSymbol()) {
    // Check if this symbol was the return of hws_send_ring_set_sq_rdy
    const MemRegion * const *BaseRegPtr = State->get<RetSymToSQBase>(Sym);
    if (BaseRegPtr) {
      const MemRegion *BaseReg = *BaseRegPtr;
      // Split states on this condition
      if (auto DV = CondV.getAs<DefinedOrUnknownSVal>()) {
        ProgramStateRef StateTrue, StateFalse;
        std::tie(StateTrue, StateFalse) = State->assume(*DV);
        bool didTransition = false;

        if (StateTrue) {
          StateTrue = StateTrue->set<SQErrBranchActive>(BaseReg, true);
          C.addTransition(StateTrue);
          didTransition = true;
        }
        if (StateFalse) {
          // Not in error branch
          StateFalse = StateFalse->remove<SQErrBranchActive>(BaseReg);
          C.addTransition(StateFalse);
          didTransition = true;
        }
        if (didTransition)
          return; // We handled branching explicitly
      }
    }
  }
  // Otherwise do nothing special; let core handle the branch.
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // We only report on the problematic cleanup: hws_send_ring_close_sq(sq)
  if (isCloseSQ(Call, C)) {
    if (Call.getNumArgs() > 0) {
      const Expr *Arg0 = Call.getArgExpr(0);
      const MemRegion *BaseReg = getSQBaseRegionFromPointerArg(Arg0, C);
      if (!BaseReg)
        return;

      const bool *WasCreated = State->get<SQCreated>(BaseReg);
      const bool *ErrActive = State->get<SQErrBranchActive>(BaseReg);

      if (WasCreated && *WasCreated && ErrActive && *ErrActive) {
        // We are in the error branch after set_sq_rdy() failed and a create was observed.
        // Calling the high-level close here may double free.
        reportWrongCleanup(Call, C);
      }
    }
    return;
  }

  // Optional: recognizing mlx5_core_destroy_sq is not necessary for reporting,
  // but included here for completeness. We don't mutate state.
  if (isDestroySQ(Call, C)) {
    // No action required.
    return;
  }
}

void SAGenTestChecker::reportWrongCleanup(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "High-level close in intermediate error path may double free; call mlx5_core_destroy_sq().", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects wrong cleanup after SQ set_rdy failure that may cause double free; use mlx5_core_destroy_sq()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
