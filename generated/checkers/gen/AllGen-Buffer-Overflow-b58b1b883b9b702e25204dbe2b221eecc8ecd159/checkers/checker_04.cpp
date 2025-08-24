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

REGISTER_MAP_WITH_PROGRAMSTATE(DeltaToIterMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
    : public Checker<
          check::Bind,
          check::PostStmt<BinaryOperator>,
          check::PostStmt<CompoundAssignOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
                                     "iov_iter count underflow risk",
                                     "Integer")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPostStmt(const CompoundAssignOperator *CAO,
                     CheckerContext &C) const;

private:
  // Helpers
  static bool isUnsignedIntegral(QualType QT);
  static const MemRegion *getVarRegionFromExpr(const Expr *E,
                                               CheckerContext &C);
  static const MemRegion *getIterBaseFromMemberExpr(const Expr *E,
                                                    CheckerContext &C);
  static bool isIovAvailExpr(const Expr *E, const MemRegion *&IterMR,
                             CheckerContext &C);
  static bool isRoundUpExpr(const Expr *E, CheckerContext &C);
  void report(const Stmt *S, CheckerContext &C) const;
};

/* ===================== Helper Implementations ===================== */

bool SAGenTestChecker::isUnsignedIntegral(QualType QT) {
  if (QT.isNull())
    return false;
  QT = QT.getCanonicalType();
  return QT->isUnsignedIntegerType();
}

const MemRegion *SAGenTestChecker::getVarRegionFromExpr(const Expr *E,
                                                        CheckerContext &C) {
  if (!E)
    return nullptr;
  if (isa<DeclRefExpr>(E->IgnoreParenCasts())) {
    const MemRegion *MR = getMemRegionFromExpr(E, C);
    if (!MR)
      return nullptr;
    return MR->getBaseRegion();
  }
  return nullptr;
}

const MemRegion *
SAGenTestChecker::getIterBaseFromMemberExpr(const Expr *E,
                                            CheckerContext &C) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenCasts();
  const auto *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return nullptr;
  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD)
    return nullptr;
  const IdentifierInfo *II = VD->getIdentifier();
  if (!II)
    return nullptr;
  // We are interested in "count" field: iter->count
  if (!II->isStr("count"))
    return nullptr;

  const Expr *Base = ME->getBase();
  if (!Base)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(Base, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

bool SAGenTestChecker::isIovAvailExpr(const Expr *E,
                                      const MemRegion *&IterMR,
                                      CheckerContext &C) {
  IterMR = nullptr;
  if (!E)
    return false;

  E = E->IgnoreParenCasts();

  // Case 1: iov_iter_count(iter)
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (ExprHasName(CE, "iov_iter_count", C) && CE->getNumArgs() == 1) {
      const Expr *Arg0 = CE->getArg(0);
      const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
      if (!MR)
        return false;
      IterMR = MR->getBaseRegion();
      return IterMR != nullptr;
    }
  }

  // Case 2: iter->count
  if (const MemRegion *MR = getIterBaseFromMemberExpr(E, C)) {
    IterMR = MR;
    return true;
  }

  return false;
}

bool SAGenTestChecker::isRoundUpExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  // Match common kernel macro/function names for rounding up.
  // Using source text via utility to be robust to macros.
  return ExprHasName(E, "round_up", C) || ExprHasName(E, "roundup", C);
}

void SAGenTestChecker::report(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Underflow risk: avail - round_up(...) may wrap, then used to decrement "
      "iter->count. Add clamp before decrement",
      N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

/* ===================== Core Logic ===================== */

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // Only record mapping for local/param variables (not fields).
  const auto *VR = dyn_cast<VarRegion>(LHSReg);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return;

  // Prefer unsigned integral (size_t-like).
  if (!isUnsignedIntegral(VD->getType()))
    return;

  if (!S)
    return;

  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return;

  E = E->IgnoreParenCasts();

  // Two cases to capture "shorten = avail - need" pattern:
  // 1) Direct initializer "size_t shorten = avail - round_up(...);"
  // 2) Simple assignment "shorten = avail - round_up(...);"
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS();
      if (!RHS)
        return;
      RHS = RHS->IgnoreParenCasts();
      const auto *Sub = dyn_cast<BinaryOperator>(RHS);
      if (!Sub || Sub->getOpcode() != BO_Sub)
        return;

      const Expr *L0 = Sub->getLHS();
      const Expr *R0 = Sub->getRHS();
      if (!L0 || !R0)
        return;

      const MemRegion *IterMR = nullptr;
      if (isIovAvailExpr(L0, IterMR, C) && IterMR && isRoundUpExpr(R0, C)) {
        State = State->set<DeltaToIterMap>(LHSReg, IterMR->getBaseRegion());
        C.addTransition(State);
      }
      return;
    } else if (BO->getOpcode() == BO_Sub) {
      // Initializer of form "size_t shorten = avail - round_up(...);"
      const Expr *L0 = BO->getLHS();
      const Expr *R0 = BO->getRHS();
      if (!L0 || !R0)
        return;

      const MemRegion *IterMR = nullptr;
      if (isIovAvailExpr(L0, IterMR, C) && IterMR && isRoundUpExpr(R0, C)) {
        State = State->set<DeltaToIterMap>(LHSReg, IterMR->getBaseRegion());
        C.addTransition(State);
      }
      return;
    }
  }
}

void SAGenTestChecker::checkPostStmt(const CompoundAssignOperator *CAO,
                                     CheckerContext &C) const {
  if (!CAO)
    return;

  if (CAO->getOpcode() != BO_SubAssign)
    return;

  // Match "iter->count -= something"
  const Expr *LHS = CAO->getLHS();
  if (!LHS)
    return;
  const MemRegion *IterMR_LHS = getIterBaseFromMemberExpr(LHS, C);
  if (!IterMR_LHS)
    return;

  const Expr *RHS = CAO->getRHS();
  if (!RHS)
    return;
  RHS = RHS->IgnoreParenCasts();

  ProgramStateRef State = C.getState();

  // Case A: "iter->count -= shorten" where shorten recorded as avail - round_up(...)
  if (const auto *DRE = dyn_cast<DeclRefExpr>(RHS)) {
    const MemRegion *DeltaMR = getVarRegionFromExpr(DRE, C);
    if (DeltaMR) {
      if (const MemRegion *const *MappedIter = State->get<DeltaToIterMap>(DeltaMR)) {
        // Ensure the delta was computed from the same iter
        if (*MappedIter && *MappedIter == IterMR_LHS) {
          report(CAO, C);
        }
      }
    }
    return;
  }

  // Case B: "iter->count -= (avail - round_up(...))"
  if (const auto *Sub = dyn_cast<BinaryOperator>(RHS)) {
    if (Sub->getOpcode() == BO_Sub) {
      const Expr *L0 = Sub->getLHS();
      const Expr *R0 = Sub->getRHS();
      const MemRegion *IterMR_RHS = nullptr;
      if (L0 && R0 && isIovAvailExpr(L0, IterMR_RHS, C) && IterMR_RHS &&
          isRoundUpExpr(R0, C) && IterMR_RHS == IterMR_LHS) {
        report(CAO, C);
      }
    }
  }
}

void SAGenTestChecker::checkPostStmt(const BinaryOperator *BO,
                                     CheckerContext &C) const {
  if (!BO)
    return;

  if (BO->getOpcode() != BO_Assign)
    return;

  // Match "iter->count = iter->count - shorten"
  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return;
  const MemRegion *IterMR_LHS = getIterBaseFromMemberExpr(LHS, C);
  if (!IterMR_LHS)
    return;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;
  RHS = RHS->IgnoreParenCasts();

  const auto *Sub = dyn_cast<BinaryOperator>(RHS);
  if (!Sub || Sub->getOpcode() != BO_Sub)
    return;

  // Ensure the subtraction is based on the same iter: "iter->count - ..."
  const Expr *SubLHS = Sub->getLHS();
  if (!SubLHS)
    return;

  bool SameIterBase = false;
  // Either "iter->count - ..." or "iov_iter_count(iter) - ..." referring to same iter.
  if (const MemRegion *IterFromMember = getIterBaseFromMemberExpr(SubLHS, C)) {
    SameIterBase = (IterFromMember == IterMR_LHS);
  } else {
    const MemRegion *IterFromAvail = nullptr;
    if (isIovAvailExpr(SubLHS, IterFromAvail, C) && IterFromAvail == IterMR_LHS)
      SameIterBase = true;
  }
  if (!SameIterBase)
    return;

  ProgramStateRef State = C.getState();

  const Expr *SubRHS = Sub->getRHS();
  if (!SubRHS)
    return;
  SubRHS = SubRHS->IgnoreParenCasts();

  // Case A: "iter->count = iter->count - shorten"
  if (const auto *DRE = dyn_cast<DeclRefExpr>(SubRHS)) {
    const MemRegion *DeltaMR = getVarRegionFromExpr(DRE, C);
    if (DeltaMR) {
      if (const MemRegion *const *MappedIter = State->get<DeltaToIterMap>(DeltaMR)) {
        if (*MappedIter && *MappedIter == IterMR_LHS) {
          report(BO, C);
        }
      }
    }
    return;
  }

  // Case B: "iter->count = iter->count - (avail - round_up(...))"
  if (const auto *InnerSub = dyn_cast<BinaryOperator>(SubRHS)) {
    if (InnerSub->getOpcode() == BO_Sub) {
      const Expr *L0 = InnerSub->getLHS();
      const Expr *R0 = InnerSub->getRHS();
      const MemRegion *IterMR_RHS = nullptr;
      if (L0 && R0 && isIovAvailExpr(L0, IterMR_RHS, C) && IterMR_RHS &&
          isRoundUpExpr(R0, C) && IterMR_RHS == IterMR_LHS) {
        report(BO, C);
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects iov_iter count underflow due to subtracting round_up(...) "
      "without clamping against available length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
