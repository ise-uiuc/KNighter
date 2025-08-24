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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state:
// - ShortenBaseMap: remembers that a particular "shorten" variable is derived
//                   from (total - round_up(...)) and ties it to the base object
//                   whose "count/length" it subtracts from (e.g. iter).
// - ShortenGuardedMap: remembers whether we've seen a guard like
//                   "if (shorten >= base->count) shorten = 0;".
REGISTER_MAP_WITH_PROGRAMSTATE(ShortenBaseMap, const MemRegion*, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(ShortenGuardedMap, const MemRegion*, bool)

namespace {
class SAGenTestChecker
  : public Checker<
      check::PostStmt<DeclStmt>,
      check::Bind,
      check::BranchCondition
    > {

   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(std::make_unique<BugType>(this, "Underflow risk in count adjustment", "Logic error")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  static bool isUnsignedIntLike(QualType QT);
  static bool exprContainsRoundUp(const Expr *E, CheckerContext &C);
  static const MemRegion* tryGetBaseRegionFromTotalExpr(const Expr *E, CheckerContext &C);
  static const MemRegion* getShortenVarRegionFromVarDecl(const VarDecl *VD, CheckerContext &C);
  static const MemRegion* getShortenVarRegionFromExpr(const Expr *E, CheckerContext &C);
  static const MemRegion* getBaseRegionFromLHS(const Expr *LHS, CheckerContext &C);

  static const DeclRefExpr* findDeclRefInExpr(const Expr *E);
  static const MemberExpr* findMemberExprInExpr(const Expr *E);
  static const CallExpr* findCallExprInExpr(const Expr *E);

  void recordShortenPattern(ProgramStateRef &State,
                            const MemRegion *ShortenReg,
                            const MemRegion *BaseReg,
                            CheckerContext &C) const;

  void markGuarded(ProgramStateRef &State, const MemRegion *ShortenReg, CheckerContext &C) const;

  void tryDetectAndReportUseSubtractingShorten(const Stmt *S,
                                               const Expr *TargetLHS,
                                               const Expr *RHSExpr,
                                               bool IsCompoundSubAssign,
                                               CheckerContext &C) const;

  void reportBug(const Stmt *S, CheckerContext &C) const;
};

// ======================== Helper Implementations ========================

bool SAGenTestChecker::isUnsignedIntLike(QualType QT) {
  if (QT.isNull())
    return false;
  return QT->isUnsignedIntegerType();
}

bool SAGenTestChecker::exprContainsRoundUp(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  // Heuristically match common names used for roundup/align.
  if (ExprHasName(E, "round_up", C)) return true;
  if (ExprHasName(E, "roundup", C)) return true;
  if (ExprHasName(E, "ALIGN", C)) return true;
  return false;
}

const MemRegion* SAGenTestChecker::tryGetBaseRegionFromTotalExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  // If it's like "iter->count" - use the base (iter).
  if (const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenImpCasts())) {
    const Expr *Base = ME->getBase();
    if (!Base) return nullptr;
    const MemRegion *MR = getMemRegionFromExpr(Base, C);
    if (!MR) return nullptr;
    return MR->getBaseRegion();
  }

  // If it's iov_iter_count(iter) - use the first argument's region as base.
  if (const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenImpCasts())) {
    if (ExprHasName(CE, "iov_iter_count", C) && CE->getNumArgs() >= 1) {
      const Expr *Arg0 = CE->getArg(0);
      const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
      if (!MR) return nullptr;
      return MR->getBaseRegion();
    }
  }

  return nullptr;
}

const MemRegion* SAGenTestChecker::getShortenVarRegionFromVarDecl(const VarDecl *VD, CheckerContext &C) {
  if (!VD) return nullptr;
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const MemRegion *MR = MRMgr.getVarRegion(VD, C.getLocationContext());
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::getShortenVarRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
    const MemRegion *MR = getMemRegionFromExpr(DRE, C);
    if (!MR) return nullptr;
    return MR->getBaseRegion();
  }
  return nullptr;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromLHS(const Expr *LHS, CheckerContext &C) {
  if (!LHS) return nullptr;
  if (const auto *ME = dyn_cast<MemberExpr>(LHS->IgnoreParenImpCasts())) {
    const Expr *Base = ME->getBase();
    if (!Base) return nullptr;
    const MemRegion *MR = getMemRegionFromExpr(Base, C);
    if (!MR) return nullptr;
    return MR->getBaseRegion();
  }
  return nullptr;
}

const DeclRefExpr* SAGenTestChecker::findDeclRefInExpr(const Expr *E) {
  if (!E) return nullptr;
  return findSpecificTypeInChildren<DeclRefExpr>(E);
}

const MemberExpr* SAGenTestChecker::findMemberExprInExpr(const Expr *E) {
  if (!E) return nullptr;
  return findSpecificTypeInChildren<MemberExpr>(E);
}

const CallExpr* SAGenTestChecker::findCallExprInExpr(const Expr *E) {
  if (!E) return nullptr;
  return findSpecificTypeInChildren<CallExpr>(E);
}

void SAGenTestChecker::recordShortenPattern(ProgramStateRef &State,
                                            const MemRegion *ShortenReg,
                                            const MemRegion *BaseReg,
                                            CheckerContext &C) const {
  if (!ShortenReg || !BaseReg) return;
  State = State->set<ShortenBaseMap>(ShortenReg, BaseReg);
  State = State->set<ShortenGuardedMap>(ShortenReg, false);
  C.addTransition(State);
}

void SAGenTestChecker::markGuarded(ProgramStateRef &State, const MemRegion *ShortenReg, CheckerContext &C) const {
  if (!ShortenReg) return;
  const bool *Old = State->get<ShortenGuardedMap>(ShortenReg);
  if (!Old || *Old == false) {
    State = State->set<ShortenGuardedMap>(ShortenReg, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportBug(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Possible unsigned underflow: subtracting rounded-up length from total without bounds check.",
      N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// Tries to detect:
// - Compound:   LHS -= shorten;
// - Simple:     LHS = LHS - shorten;
// and report if 'shorten' maps to the same base object as LHS and not guarded.
void SAGenTestChecker::tryDetectAndReportUseSubtractingShorten(const Stmt *S,
                                                               const Expr *TargetLHS,
                                                               const Expr *RHSExpr,
                                                               bool IsCompoundSubAssign,
                                                               CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!TargetLHS || !RHSExpr)
    return;

  // Get the base region for LHS like "iter->count".
  const MemRegion *LHSBase = getBaseRegionFromLHS(TargetLHS, C);
  if (!LHSBase)
    return;

  const MemRegion *ShortenReg = nullptr;

  if (IsCompoundSubAssign) {
    // Pattern: X -= shorten
    if (const DeclRefExpr *DR = findDeclRefInExpr(RHSExpr)) {
      const MemRegion *MR = getMemRegionFromExpr(DR, C);
      if (MR) ShortenReg = MR->getBaseRegion();
    }
  } else {
    // Pattern: X = X - shorten
    const auto *BOSub = dyn_cast<BinaryOperator>(RHSExpr->IgnoreParenImpCasts());
    if (!BOSub || BOSub->getOpcode() != BO_Sub)
      return;

    // RHS must be 'LHS_like - shorten'
    const Expr *RHSLHS = BOSub->getLHS();
    const Expr *RHSRHS = BOSub->getRHS();

    // Check LHS of subtraction refers to same base object as assignment LHS
    const MemRegion *RHSLHSBase = getBaseRegionFromLHS(RHSLHS, C);
    if (!RHSLHSBase || RHSLHSBase != LHSBase)
      return;

    if (const DeclRefExpr *DR = findDeclRefInExpr(RHSRHS)) {
      const MemRegion *MR = getMemRegionFromExpr(DR, C);
      if (MR) ShortenReg = MR->getBaseRegion();
    }
  }

  if (!ShortenReg)
    return;

  // Verify that ShortenReg is a tracked "shorten" derived from this base object.
  const MemRegion *MappedBase = State->get<ShortenBaseMap>(ShortenReg);
  if (!MappedBase || MappedBase != LHSBase)
    return;

  const bool *Guarded = State->get<ShortenGuardedMap>(ShortenReg);
  if (Guarded && *Guarded)
    return; // A guard/clamp was observed earlier.

  // Report
  reportBug(S, C);

  // Optionally, drop mapping to avoid duplicate reports on same path.
  State = State->remove<ShortenBaseMap>(ShortenReg);
  State = State->remove<ShortenGuardedMap>(ShortenReg);
  C.addTransition(State);
}

// ======================== Checker Callbacks ========================

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  ProgramStateRef State = C.getState();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!VD->hasInit())
      continue;

    // Only track unsigned-like variables (e.g., size_t).
    if (!isUnsignedIntLike(VD->getType()))
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    // Look for: shorten = U - round_up(...)
    const auto *BOSub = dyn_cast<BinaryOperator>(Init->IgnoreParenImpCasts());
    if (!BOSub || BOSub->getOpcode() != BO_Sub)
      continue;

    const Expr *U = BOSub->getLHS();
    const Expr *W = BOSub->getRHS();
    if (!U || !W)
      continue;

    if (!exprContainsRoundUp(W, C))
      continue;

    const MemRegion *BaseReg = tryGetBaseRegionFromTotalExpr(U, C);
    if (!BaseReg)
      continue;

    const MemRegion *ShortenReg = getShortenVarRegionFromVarDecl(VD, C);
    if (!ShortenReg)
      continue;

    recordShortenPattern(State, ShortenReg, BaseReg, C);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  ProgramStateRef State = C.getState();

  // A) Record shorten = U - round_up(...) assignments (non-declarative).
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      // Only track if LHS variable is unsigned-like.
      if (!LHS || !isUnsignedIntLike(LHS->getType()))
        /* fallthrough to other checks */;

      // Look for RHS: U - round_up(...)
      const auto *BOSub = dyn_cast<BinaryOperator>(RHS ? RHS->IgnoreParenImpCasts() : nullptr);
      if (BOSub && BOSub->getOpcode() == BO_Sub) {
        const Expr *U = BOSub->getLHS();
        const Expr *W = BOSub->getRHS();
        if (U && W && exprContainsRoundUp(W, C)) {
          const MemRegion *BaseReg = tryGetBaseRegionFromTotalExpr(U, C);
          const MemRegion *ShortenReg = getShortenVarRegionFromExpr(LHS, C);
          if (BaseReg && ShortenReg) {
            recordShortenPattern(State, ShortenReg, BaseReg, C);
          }
        }
      }

      // B2) Detect "X = X - shorten" pattern for use.
      tryDetectAndReportUseSubtractingShorten(S, LHS, RHS, /*IsCompoundSubAssign*/false, C);
      return;
    }
  }

  // B1) Detect "X -= shorten" pattern for use.
  if (const auto *CAO = dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_SubAssign) {
      const Expr *LHS = CAO->getLHS();
      const Expr *RHS = CAO->getRHS();
      tryDetectAndReportUseSubtractingShorten(S, LHS, RHS, /*IsCompoundSubAssign*/true, C);
      return;
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const auto *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  const auto *BO = dyn_cast<BinaryOperator>(CondE->IgnoreParenImpCasts());
  if (!BO) {
    C.addTransition(State);
    return;
  }

  BinaryOperator::Opcode Op = BO->getOpcode();
  // We consider comparisons which could indicate a guard:
  // shorten >= base->count, shorten > base->count, etc.
  if (!(Op == BO_GE || Op == BO_GT || Op == BO_LE || Op == BO_LT || Op == BO_EQ || Op == BO_NE)) {
    C.addTransition(State);
    return;
  }

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS) {
    C.addTransition(State);
    return;
  }

  // Try to find a 'shorten' variable (DeclRefExpr) on one side and a base 'count'
  // reference (MemberExpr or iov_iter_count(base)) on the other side.
  const DeclRefExpr *DRE_L = findDeclRefInExpr(LHS);
  const DeclRefExpr *DRE_R = findDeclRefInExpr(RHS);

  const MemRegion *ShortenReg = nullptr;
  const MemRegion *OtherBase = nullptr;
  const Expr *OtherExpr = nullptr;

  if (DRE_L) {
    const MemRegion *MR = getMemRegionFromExpr(DRE_L, C);
    if (MR) {
      MR = MR->getBaseRegion();
      // Ensure this DRE is one of tracked 'shorten' variables
      if (State->contains<ShortenBaseMap>(MR)) {
        ShortenReg = MR;
        OtherExpr = RHS;
      }
    }
  }

  if (!ShortenReg && DRE_R) {
    const MemRegion *MR = getMemRegionFromExpr(DRE_R, C);
    if (MR) {
      MR = MR->getBaseRegion();
      if (State->contains<ShortenBaseMap>(MR)) {
        ShortenReg = MR;
        OtherExpr = LHS;
      }
    }
  }

  if (!ShortenReg || !OtherExpr) {
    C.addTransition(State);
    return;
  }

  // Find base on the other side.
  if (const auto *ME = findMemberExprInExpr(OtherExpr)) {
    OtherBase = getBaseRegionFromLHS(ME, C);
  } else if (const auto *CE = findCallExprInExpr(OtherExpr)) {
    if (ExprHasName(CE, "iov_iter_count", C) && CE->getNumArgs() >= 1) {
      const MemRegion *MR = getMemRegionFromExpr(CE->getArg(0), C);
      if (MR) OtherBase = MR->getBaseRegion();
    }
  }

  if (!OtherBase) {
    // Heuristic fallback: if we cannot resolve base of the other side,
    // conservatively do nothing.
    C.addTransition(State);
    return;
  }

  const MemRegion *MappedBase = State->get<ShortenBaseMap>(ShortenReg);
  if (MappedBase && MappedBase == OtherBase) {
    markGuarded(State, ShortenReg, C);
    return;
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsigned underflow when subtracting rounded-up length from a total without a guard",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
