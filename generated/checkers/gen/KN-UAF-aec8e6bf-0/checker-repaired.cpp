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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track resource pointer state.
// 0 = OpenOrUnknown (default / not tracked)
// 1 = Closed (freed/released but not set to NULL)
// 2 = Nullified (explicitly set to NULL after close)
REGISTER_MAP_WITH_PROGRAMSTATE(ResourceStateMap, const MemRegion *, unsigned)
// Program state: track aliasing, mapping alias region -> root region.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)

namespace {

enum ResState : unsigned {
  OpenOrUnknown = 0,
  Closed = 1,
  Nullified = 2
};

class SAGenTestChecker
    : public Checker<
          check::PreCall,
          check::PostCall,
          check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double close / use-after-free (not nullified)",
                       "Resource Handling")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool isCloseLike(const CallEvent &Call, CheckerContext &C);
  static const MemRegion *getRootAlias(const MemRegion *R, ProgramStateRef State);
  static ProgramStateRef setAlias(ProgramStateRef State, const MemRegion *Alias,
                                  const MemRegion *Target);
  static ProgramStateRef setResState(ProgramStateRef State, const MemRegion *R,
                                     unsigned NewState);
  static unsigned getResState(ProgramStateRef State, const MemRegion *R);
  static bool isNullSVal(SVal V);
  static bool isNonNullPointerish(SVal V, ASTContext &ACtx);
};

bool SAGenTestChecker::isCloseLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Use source-text-based name check for robustness.
  // Known close-like functions for file pointers in kernel/user space.
  if (ExprHasName(OE, "fput", C))
    return true;
  if (ExprHasName(OE, "filp_close", C))
    return true;
  if (ExprHasName(OE, "fclose", C))
    return true;

  // Optionally extend if needed.
  return false;
}

const MemRegion *SAGenTestChecker::getRootAlias(const MemRegion *R, ProgramStateRef State) {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  // Follow alias chain with a simple loop guard.
  for (unsigned i = 0; i < 8; ++i) {
    if (!Cur)
      break;
    if (const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur)) {
      const MemRegion *Next = *NextPtr;
      const MemRegion *NextBase = Next->getBaseRegion();
      if (!NextBase || NextBase == Cur)
        break;
      Cur = NextBase;
      continue;
    }
    break;
  }
  return Cur;
}

ProgramStateRef SAGenTestChecker::setAlias(ProgramStateRef State, const MemRegion *Alias,
                                           const MemRegion *Target) {
  if (!State || !Alias || !Target)
    return State;
  const MemRegion *AliasB = Alias->getBaseRegion();
  const MemRegion *TargetB = getRootAlias(Target->getBaseRegion(), State);
  if (!AliasB || !TargetB)
    return State;
  State = State->set<PtrAliasMap>(AliasB, TargetB);
  // Also set reverse alias (symmetric) to strengthen tracking.
  State = State->set<PtrAliasMap>(TargetB, AliasB);
  return State;
}

ProgramStateRef SAGenTestChecker::setResState(ProgramStateRef State, const MemRegion *R,
                                              unsigned NewState) {
  if (!State || !R)
    return State;
  const MemRegion *Root = getRootAlias(R, State);
  if (!Root)
    return State;

  if (NewState == OpenOrUnknown) {
    // Clearing state when overwritten with new non-null value.
    State = State->remove<ResourceStateMap>(Root);
  } else {
    State = State->set<ResourceStateMap>(Root, NewState);
  }
  return State;
}

unsigned SAGenTestChecker::getResState(ProgramStateRef State, const MemRegion *R) {
  if (!State || !R)
    return OpenOrUnknown;
  const MemRegion *Root = getRootAlias(R, State);
  if (!Root)
    return OpenOrUnknown;
  if (const unsigned *S = State->get<ResourceStateMap>(Root))
    return *S;
  return OpenOrUnknown;
}

bool SAGenTestChecker::isNullSVal(SVal V) {
  if (auto L = V.getAs<Loc>()) {
    if (auto CI = L->getAs<loc::ConcreteInt>()) {
      return CI->getValue().isZero();
    }
  }
  if (auto CI = V.getAs<nonloc::ConcreteInt>()) {
    return CI->getValue().isZero();
  }
  return false;
}

bool SAGenTestChecker::isNonNullPointerish(SVal V, ASTContext &ACtx) {
  // Heuristic: if we have a region or a non-zero concrete int as pointer.
  if (V.getAsRegion())
    return true;

  if (auto L = V.getAs<Loc>()) {
    if (auto CI = L->getAs<loc::ConcreteInt>()) {
      return !CI->getValue().isZero();
    }
    // Unknown pointer value: can't assert non-null.
    return false;
  }

  // For typed ints used as pointers, avoid guessing.
  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCloseLike(Call, C))
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  if (Call.getNumArgs() < 1)
    return;

  // Arg0 should be the file pointer being closed.
  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *MR = Arg0.getAsRegion();
  if (!MR) {
    // As a fallback, try extracting region from the expression directly.
    if (const Expr *AE = Call.getArgExpr(0)) {
      MR = getMemRegionFromExpr(AE, C);
    }
  }
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark as Closed after successful close-like call.
  State = setResState(State, MR, Closed);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCloseLike(Call, C))
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *MR = Arg0.getAsRegion();
  if (!MR) {
    if (const Expr *AE = Call.getArgExpr(0)) {
      MR = getMemRegionFromExpr(AE, C);
    }
  }
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  unsigned RS = getResState(State, MR);
  if (RS == Closed) {
    // Second close without nullification.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Double close: pointer was closed but not set to NULL", N);
    R->addRange(Call.getSourceRange());
    C.emitReport(std::move(R));
    return;
  }

  // If already nullified, it's fine (no report).
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State)
    return;

  // Track aliasing: if binding a pointer value to a pointer location, record alias.
  if (const MemRegion *LHS = Loc.getAsRegion()) {
    LHS = LHS->getBaseRegion();
    if (LHS) {
      if (const MemRegion *RHS = Val.getAsRegion()) {
        RHS = RHS->getBaseRegion();
        if (RHS) {
          State = setAlias(State, LHS, RHS);
        }
      }
    }
  }

  // Nullification detection.
  if (const MemRegion *LHS = Loc.getAsRegion()) {
    LHS = LHS->getBaseRegion();
    if (LHS) {
      if (isNullSVal(Val)) {
        // Explicitly set to NULL.
        State = setResState(State, LHS, Nullified);
      } else if (isNonNullPointerish(Val, C.getASTContext())) {
        // Overwrite with a new non-null pointer -> not a stale closed pointer anymore.
        State = setResState(State, LHS, OpenOrUnknown);
      }
    }
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double close when a resource pointer is closed and not set to NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
