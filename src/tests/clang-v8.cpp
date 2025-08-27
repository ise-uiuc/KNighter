//===- SAGenTestChecker.cpp --------------------------------------*- C++-*-===//
//
//  Minimal CSA plugin checker (LLVM/Clang 18).
//  Pattern: after establishing (P == Q) on a branch, later dereference of P
//  (or Q) that may be null is suspicious.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

// Keep REGISTER_* at global scope (NOT inside namespaces), otherwise you'll get
// “specialization in different namespace” errors.
REGISTER_MAP_WITH_PROGRAMSTATE(NullEqMap, const VarDecl *, const VarDecl *)

namespace {

static const VarDecl *getVarDeclFromExpr(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());
  return nullptr;
}

class NullEqualityThenDerefChecker
    : public Checker<check::BranchCondition, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  NullEqualityThenDerefChecker()
      : BT(std::make_unique<BugType>(
            this, "Possible null dereference after equality", "Nullness")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  void reportBug(const VarDecl *VD, const Stmt *S, CheckerContext &C) const;
};

void NullEqualityThenDerefChecker::checkBranchCondition(const Stmt *Condition,
                                                        CheckerContext &C) const {
  const auto *BO = dyn_cast<BinaryOperator>(Condition);
  if (!BO)
    return;

  if (BO->getOpcode() != BO_EQ)
    return;

  const VarDecl *VL = getVarDeclFromExpr(BO->getLHS());
  const VarDecl *VR = getVarDeclFromExpr(BO->getRHS());
  if (!VL || !VR)
    return;

  if (!VL->getType()->isAnyPointerType() || !VR->getType()->isAnyPointerType())
    return;

  // Split states by condition truth value.
  auto CondV = C.getSVal(BO).getAs<DefinedOrUnknownSVal>();
  if (!CondV)
    return;

  ProgramStateRef St = C.getState();
  ProgramStateRef StT = St->assume(*CondV, /*Assumption=*/true);
  ProgramStateRef StF = St->assume(*CondV, /*Assumption=*/false);

  // On TRUE branch of (P == Q), record the relation in state.
  if (StT) {
    StT = StT->set<NullEqMap>(VL, VR);
    StT = StT->set<NullEqMap>(VR, VL);
    C.addTransition(StT);
  }
  if (StF)
    C.addTransition(StF);
}

void NullEqualityThenDerefChecker::checkLocation(SVal Loc, bool IsLoad,
                                                 const Stmt *S,
                                                 CheckerContext &C) const {
  // Only warn for loads (reads) to keep it minimal.
  if (!IsLoad)
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  const auto *VR = dyn_cast_or_null<VarRegion>(R->getBaseRegion());
  if (!VR)
    return;

  const VarDecl *VD = dyn_cast_or_null<VarDecl>(VR->getDecl());
  if (!VD || !VD->getType()->isAnyPointerType())
    return;

  ProgramStateRef State = C.getState();

  // get<NullEqMap> returns a pointer to the mapped value (lookup_type).
  if (const VarDecl *const *PeerPtr = State->get<NullEqMap>(VD)) {
    // We only need the fact "VD participated in equality".
    // Now check if VD's current value may be null.
    SValBuilder &SVB = C.getSValBuilder();
    SVal PtrV = State->getSVal(loc::MemRegionVal(VR));

    auto DV = PtrV.getAs<DefinedOrUnknownSVal>();
    if (!DV)
      return;

    // Use zero-of-pointer-type as NULL.
    DefinedOrUnknownSVal NullV =
        SVB.makeZeroVal(VD->getType()).castAs<DefinedOrUnknownSVal>();

    DefinedOrUnknownSVal IsNull = SVB.evalEQ(State, *DV, NullV);
    ProgramStateRef StNull = State->assume(IsNull, /*Assumption=*/true);

    if (StNull)
      reportBug(VD, S, C);
  }
}

void NullEqualityThenDerefChecker::reportBug(const VarDecl *VD, const Stmt *S,
                                             CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible null dereference due to (P == Q) relation", N);
  if (S)
    Rpt->addRange(S->getSourceRange());
  C.emitReport(std::move(Rpt));
}

} // end anonymous namespace

// ----- Plugin registration -----
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<NullEqualityThenDerefChecker>(
      "custom.SAGenTestChecker",
      "Warns on possible null dereference after (P == Q) relation", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
