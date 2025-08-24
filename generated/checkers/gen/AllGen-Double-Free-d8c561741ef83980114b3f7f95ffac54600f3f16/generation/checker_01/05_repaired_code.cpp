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
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

//==================== Program State Customization ====================//

// Map return symbol of hws_send_ring_create_sq() to the SQ object region.
REGISTER_MAP_WITH_PROGRAMSTATE(CreateRetSymMap, SymbolRef, const MemRegion*)
// Map return symbol of hws_send_ring_set_sq_rdy() to the SQ object region.
REGISTER_MAP_WITH_PROGRAMSTATE(SetRdyRetSymMap, SymbolRef, const MemRegion*)
// Track the state of each SQ object region: 1=Created, 2=SetRdyFailedPendingDestroy
REGISTER_MAP_WITH_PROGRAMSTATE(SQStateMap, const MemRegion*, unsigned)

namespace {

static const unsigned SQ_CREATED = 1;
static const unsigned SQ_SET_RDY_FAILED = 2;

class SAGenTestChecker
    : public Checker<
          check::PostCall,
          check::PreCall,
          eval::Assume> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Mismatched cleanup after partial init",
                       "Resource Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                             bool Assumption) const;

private:
  // Classification helpers
  bool isCreateCall(const CallEvent &Call, CheckerContext &C) const;
  bool isSetReadyCall(const CallEvent &Call, CheckerContext &C) const;
  bool isCloseCall(const CallEvent &Call, CheckerContext &C) const;
  bool isDestroyCall(const CallEvent &Call, CheckerContext &C) const;

  // Extractors for SQ region
  const MemRegion *getSQRegionFromCreate(const CallEvent &Call,
                                         CheckerContext &C) const;
  const MemRegion *getSQRegionFromSetRdy(const CallEvent &Call,
                                         CheckerContext &C) const;
  const MemRegion *getSQRegionFromClose(const CallEvent &Call,
                                        CheckerContext &C) const;
  const MemRegion *getSQRegionFromDestroy(const CallEvent &Call,
                                          CheckerContext &C) const;

  // Utility
  const MemRegion *getBaseRegionFromExpr(const Expr *E,
                                         CheckerContext &C) const;

  void reportMismatchedClose(const CallEvent &Call, CheckerContext &C) const;
};

//==================== Helper Implementations ====================//

bool SAGenTestChecker::isCreateCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "hws_send_ring_create_sq", C);
}

bool SAGenTestChecker::isSetReadyCall(const CallEvent &Call,
                                      CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "hws_send_ring_set_sq_rdy", C);
}

bool SAGenTestChecker::isCloseCall(const CallEvent &Call,
                                   CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "hws_send_ring_close_sq", C);
}

bool SAGenTestChecker::isDestroyCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "mlx5_core_destroy_sq", C) ||
         ExprHasName(E, "hws_send_ring_destroy_sq", C);
}

const MemRegion *SAGenTestChecker::getBaseRegionFromExpr(const Expr *E,
                                                         CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

const MemRegion *SAGenTestChecker::getSQRegionFromCreate(const CallEvent &Call,
                                                         CheckerContext &C) const {
  // hws_send_ring_create_sq(..., sq, ...)
  // Index 4 is 'sq' (0-based).
  if (Call.getNumArgs() <= 4)
    return nullptr;
  const Expr *Arg = Call.getArgExpr(4);
  return getBaseRegionFromExpr(Arg, C);
}

const MemRegion *SAGenTestChecker::getSQRegionFromSetRdy(const CallEvent &Call,
                                                         CheckerContext &C) const {
  // hws_send_ring_set_sq_rdy(mdev, sq->sqn)
  if (Call.getNumArgs() <= 1)
    return nullptr;
  const Expr *Arg = Call.getArgExpr(1);
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg);
  if (!ME)
    return nullptr;

  // Ensure the member is 'sqn'
  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD)
    return nullptr;
  if (!VD->getName().equals("sqn"))
    return nullptr;

  const Expr *Base = ME->getBase();
  return getBaseRegionFromExpr(Base, C);
}

const MemRegion *SAGenTestChecker::getSQRegionFromClose(const CallEvent &Call,
                                                        CheckerContext &C) const {
  // hws_send_ring_close_sq(sq)
  if (Call.getNumArgs() < 1)
    return nullptr;
  const Expr *Arg = Call.getArgExpr(0);
  return getBaseRegionFromExpr(Arg, C);
}

const MemRegion *SAGenTestChecker::getSQRegionFromDestroy(const CallEvent &Call,
                                                          CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return nullptr;

  // hws_send_ring_destroy_sq(mdev, sq)
  if (ExprHasName(E, "hws_send_ring_destroy_sq", C)) {
    if (Call.getNumArgs() <= 1)
      return nullptr;
    const Expr *Arg = Call.getArgExpr(1);
    return getBaseRegionFromExpr(Arg, C);
  }

  // mlx5_core_destroy_sq(mdev, sq->sqn)
  if (ExprHasName(E, "mlx5_core_destroy_sq", C)) {
    if (Call.getNumArgs() <= 1)
      return nullptr;
    const Expr *Arg = Call.getArgExpr(1);
    const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg);
    if (!ME)
      return nullptr;

    const ValueDecl *VD = ME->getMemberDecl();
    if (!VD || !VD->getName().equals("sqn"))
      return nullptr;

    const Expr *Base = ME->getBase();
    return getBaseRegionFromExpr(Base, C);
  }

  return nullptr;
}

//==================== Core Logic ====================//

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isCreateCall(Call, C)) {
    const MemRegion *SQReg = getSQRegionFromCreate(Call, C);
    if (!SQReg)
      return;

    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (!RetSym)
      return;

    State = State->set<CreateRetSymMap>(RetSym, SQReg);
    C.addTransition(State);
    return;
  }

  if (isSetReadyCall(Call, C)) {
    const MemRegion *SQReg = getSQRegionFromSetRdy(Call, C);
    if (!SQReg)
      return;

    SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
    if (!RetSym)
      return;

    State = State->set<SetRdyRetSymMap>(RetSym, SQReg);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isCloseCall(Call, C)) {
    const MemRegion *R = getSQRegionFromClose(Call, C);
    if (!R)
      return;

    const unsigned *St = State->get<SQStateMap>(R);
    if (St && *St == SQ_SET_RDY_FAILED) {
      reportMismatchedClose(Call, C);
    }
    return;
  }

  if (isDestroyCall(Call, C)) {
    const MemRegion *R = getSQRegionFromDestroy(Call, C);
    if (!R)
      return;

    // Correct undo path, clear state for this SQ.
    State = State->remove<SQStateMap>(R);
    C.addTransition(State);
    return;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond,
                                             bool Assumption) const {
  SymbolRef S = Cond.getAsSymbol();
  if (!S)
    return State;

  // Handle create_sq return symbol: success iff Assumption == false for "if (err)".
  if (const MemRegion *const *RPtr = State->get<CreateRetSymMap>(S)) {
    const MemRegion *R = *RPtr;
    State = State->remove<CreateRetSymMap>(S);
    if (!Assumption) { // err == 0 -> created
      State = State->set<SQStateMap>(R, SQ_CREATED);
    }
    return State;
  }

  // Handle set_sq_rdy return symbol: failure iff Assumption == true for "if (err)".
  if (const MemRegion *const *RPtr = State->get<SetRdyRetSymMap>(S)) {
    const MemRegion *R = *RPtr;
    State = State->remove<SetRdyRetSymMap>(S);
    if (Assumption) { // err != 0 -> set_rdy failed
      // To reduce false positives, prefer upgrading only if was created.
      if (const unsigned *St = State->get<SQStateMap>(R)) {
        if (*St == SQ_CREATED) {
          State = State->set<SQStateMap>(R, SQ_SET_RDY_FAILED);
        }
      }
    }
    return State;
  }

  return State;
}

void SAGenTestChecker::reportMismatchedClose(const CallEvent &Call,
                                             CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use destroy after set_sq_rdy() failure; close() here may double free.",
      N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects mismatched close vs destroy after set_sq_rdy failure in mlx5 SQ setup",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
