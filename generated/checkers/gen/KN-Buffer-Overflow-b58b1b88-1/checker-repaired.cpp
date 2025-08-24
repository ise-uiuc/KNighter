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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallVector.h"
#include <utility>
#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map a temporary variable (e.g., "shorten") to the iov_iter MemRegion used to compute it.
REGISTER_MAP_WITH_PROGRAMSTATE(ShortenToIterRegion, const VarDecl*, const MemRegion*)

namespace {

// Helper: is IntegerLiteral zero
static bool isIntegerLiteralZero(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 0;
  return false;
}

// Helper: does expression look like round-up/align operation (by name)
static bool isRoundUpLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "round_up", C) || ExprHasName(E, "ALIGN", C) ||
         ExprHasName(E, "roundup", C);
}

// Helper: find a CallExpr to iov_iter_count(...) inside E and extract the iter MemRegion base.
static bool extractIterRegionFromIovIterCount(const Expr *E,
                                              CheckerContext &C,
                                              const MemRegion *&OutIterBase) {
  OutIterBase = nullptr;
  if (!E) return false;

  const CallExpr *Call = nullptr;
  // If E itself is a call, prefer that; else search in children.
  if (const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenImpCasts()))
    Call = CE;
  else
    Call = findSpecificTypeInChildren<CallExpr>(E);

  if (!Call) return false;
  // Robust name check by source text
  if (!ExprHasName(Call, "iov_iter_count", C))
    return false;

  if (Call->getNumArgs() < 1) return false;
  const Expr *Arg0 = Call->getArg(0);
  if (!Arg0) return false;

  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR) return false;
  MR = MR->getBaseRegion();
  if (!MR) return false;

  OutIterBase = MR;
  return true;
}

// Helper: check whether RHS is an inline pattern "iov_iter_count(iter) - round_up(...)"
// and that the iter base equals IterBase.
static bool isInlineShortenSubPattern(const Expr *RHS, CheckerContext &C,
                                      const MemRegion *IterBase) {
  if (!RHS || !IterBase) return false;
  const auto *BO = dyn_cast<BinaryOperator>(RHS->IgnoreParenImpCasts());
  if (!BO || BO->getOpcode() != BO_Sub) return false;

  const Expr *LHS = BO->getLHS();
  const Expr *R = BO->getRHS();
  if (!LHS || !R) return false;

  const MemRegion *FoundIterBase = nullptr;
  if (!extractIterRegionFromIovIterCount(LHS, C, FoundIterBase))
    return false;
  if (FoundIterBase != IterBase)
    return false;

  // RHS of subtraction should be round-up-like
  if (!isRoundUpLikeExpr(R, C))
    return false;

  return true;
}

// Helper: If E is a DeclRefExpr to a VarDecl recorded as a shorten-like temp,
// and its iter-region equals IterBase. Optionally return the VarDecl via OutVD.
static bool isRecordedShortenDeclRefForIter(const Expr *E, CheckerContext &C,
                                            const MemRegion *IterBase,
                                            const VarDecl *&OutVD) {
  OutVD = nullptr;
  if (!E || !IterBase) return false;

  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  if (!DRE) return false;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD) return false;

  ProgramStateRef State = C.getState();
  const MemRegion *const *Recorded = State->get<ShortenToIterRegion>(VD);
  if (!Recorded) return false;

  if ((*Recorded)->getBaseRegion() == IterBase) {
    OutVD = VD;
    return true;
  }
  return false;
}

// Helper: get iter base MemRegion from MemberExpr that accesses ".count".
static const MemRegion *getIterBaseFromCountMember(const Expr *LHS, CheckerContext &C) {
  if (!LHS) return nullptr;
  const auto *ME = dyn_cast<MemberExpr>(LHS->IgnoreParenImpCasts());
  if (!ME) return nullptr;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD) return nullptr;

  if (VD->getName() != "count")
    return nullptr;

  const Expr *BaseE = ME->getBase();
  if (!BaseE) return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR) return nullptr;

  MR = MR->getBaseRegion();
  return MR;
}

// Helper: is expression a MemberExpr ".count" for the given iter base?
static bool isCountMemberForIterBase(const Expr *E, CheckerContext &C,
                                     const MemRegion *IterBase) {
  const MemRegion *MR = getIterBaseFromCountMember(E, C);
  return MR && MR == IterBase;
}

// Helper: does Cond look like "ShortenVD >= iter->count" (or >) where iter base matches?
static bool isClampConditionForShorten(const Expr *Cond, CheckerContext &C,
                                       const VarDecl *ShortenVD,
                                       const MemRegion *IterBase) {
  if (!Cond || !ShortenVD || !IterBase) return false;
  Cond = Cond->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;
  BinaryOperator::Opcode Op = BO->getOpcode();
  if (!(Op == BO_GE || Op == BO_GT))
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto IsShorten = [&](const Expr *E) -> bool {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      return DRE->getDecl() == ShortenVD;
    return false;
  };

  // Two orders: shorten >= iter->count OR iter->count <= shorten (normalized as above)
  if (IsShorten(LHS) && isCountMemberForIterBase(RHS, C, IterBase))
    return true;
  if (IsShorten(RHS) && isCountMemberForIterBase(LHS, C, IterBase))
    return true;

  return false;
}

// Helper: recursively search in S for an assignment "ShortenVD = 0;"
static bool containsAssignZeroToVar(const Stmt *S, const VarDecl *ShortenVD) {
  if (!S || !ShortenVD) return false;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      const auto *LDRE = dyn_cast<DeclRefExpr>(L);
      if (LDRE && LDRE->getDecl() == ShortenVD && isIntegerLiteralZero(R))
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (Child && containsAssignZeroToVar(Child, ShortenVD))
      return true;
  }
  return false;
}

// Helper: Look within the same enclosing CompoundStmt for a nearby guard:
// if (shorten >= iter->count) shorten = 0;
static bool hasClampGuardNear(const Stmt *Anchor,
                              const VarDecl *ShortenVD,
                              const MemRegion *IterBase,
                              CheckerContext &C) {
  if (!Anchor || !ShortenVD || !IterBase) return false;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(Anchor, C);
  if (!CS) return false;

  // Materialize body into an indexable container.
  llvm::SmallVector<const Stmt *, 16> Body;
  for (const Stmt *S : CS->body())
    Body.push_back(S);

  // Find the index of the statement that contains Anchor
  unsigned Idx = 0;
  int AnchorIdx = -1;

  for (const Stmt *S : Body) {
    bool Found = false;

    // Try to see if this statement contains the anchor
    if (isa<CompoundAssignOperator>(Anchor)) {
      const auto *CAO = cast<CompoundAssignOperator>(Anchor);
      const auto *X = findSpecificTypeInChildren<CompoundAssignOperator>(S);
      if (X == CAO)
        Found = true;
    } else if (isa<BinaryOperator>(Anchor)) {
      const auto *BOA = cast<BinaryOperator>(Anchor);
      const auto *X = findSpecificTypeInChildren<BinaryOperator>(S);
      if (X == BOA)
        Found = true;
    }

    if (Found) {
      AnchorIdx = static_cast<int>(Idx);
      break;
    }
    ++Idx;
  }

  if (AnchorIdx < 0)
    return false;

  // Look back up to 4 statements
  int Start = std::max(0, AnchorIdx - 4);
  for (int I = AnchorIdx - 1; I >= Start; --I) {
    const Stmt *Prev = Body[I];
    if (!Prev) continue;

    const auto *IfS = dyn_cast<IfStmt>(Prev);
    if (!IfS) continue;

    const Expr *Cond = IfS->getCond();
    if (!Cond) continue;

    if (!isClampConditionForShorten(Cond, C, ShortenVD, IterBase))
      continue;

    const Stmt *Then = IfS->getThen();
    if (!Then) continue;

    if (containsAssignZeroToVar(Then, ShortenVD))
      return true;
  }

  return false;
}

class SAGenTestChecker
  : public Checker<
      check::PostStmt<DeclStmt>,
      check::PostStmt<CompoundAssignOperator>,
      check::PostStmt<BinaryOperator>
    > {

   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "iov_iter count underflow", "Arithmetic")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkPostStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const;
      void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;

   private:
      void recordShortenIfMatch(const VarDecl *VD, const Expr *Init, CheckerContext &C) const;
      void recordShortenOnAssignIfMatch(const BinaryOperator *BO, CheckerContext &C) const;

      void maybeReportOnSubAssign(const CompoundAssignOperator *CAO, CheckerContext &C) const;
      void maybeReportOnAssignCountSub(const BinaryOperator *BO, CheckerContext &C) const;

      void reportIssue(const Stmt *S, CheckerContext &C) const {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N) return;
        auto R = std::make_unique<PathSensitiveBugReport>(
            *BT, "Subtracting a rounded-up length from iov_iter->count may underflow; clamp before subtracting", N);
        if (S)
          R->addRange(S->getSourceRange());
        C.emitReport(std::move(R));
      }
};

void SAGenTestChecker::recordShortenIfMatch(const VarDecl *VD, const Expr *Init, CheckerContext &C) const {
  if (!VD || !Init) return;

  const auto *BO = dyn_cast<BinaryOperator>(Init->IgnoreParenImpCasts());
  if (!BO || BO->getOpcode() != BO_Sub) return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS) return;

  const MemRegion *IterBase = nullptr;
  if (!extractIterRegionFromIovIterCount(LHS, C, IterBase))
    return;

  if (!isRoundUpLikeExpr(RHS, C))
    return;

  ProgramStateRef State = C.getState();
  if (!IterBase) return;
  IterBase = IterBase->getBaseRegion();
  if (!IterBase) return;

  State = State->set<ShortenToIterRegion>(VD, IterBase);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS) return;
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD) continue;
    if (!VD->hasInit()) continue;

    const Expr *Init = VD->getInit();
    recordShortenIfMatch(VD, Init, C);
  }
}

// Handle: iter->count -= shorten; or iter->count -= (iov_iter_count(iter) - round_up(...))
void SAGenTestChecker::maybeReportOnSubAssign(const CompoundAssignOperator *CAO, CheckerContext &C) const {
  if (!CAO) return;
  if (CAO->getOpcode() != BO_SubAssign)
    return;

  const Expr *LHS = CAO->getLHS();
  const Expr *RHS = CAO->getRHS();
  if (!LHS || !RHS) return;

  const MemRegion *IterBase = getIterBaseFromCountMember(LHS, C);
  if (!IterBase) return;

  // Variant 1: RHS is a recorded shorten variable for this iter
  const VarDecl *ShortenVD = nullptr;
  bool Matches = isRecordedShortenDeclRefForIter(RHS, C, IterBase, ShortenVD);

  // Variant 2: RHS is inline "iov_iter_count(iter) - round_up(...)"
  if (!Matches)
    Matches = isInlineShortenSubPattern(RHS, C, IterBase);

  if (!Matches)
    return;

  // If we have a recorded variable, try to find a guard nearby: if (shorten >= iter->count) shorten = 0;
  if (ShortenVD && hasClampGuardNear(CAO, ShortenVD, IterBase, C))
    return;

  reportIssue(CAO, C);
}

void SAGenTestChecker::checkPostStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const {
  maybeReportOnSubAssign(CAO, C);
}

// Record: shorten = iov_iter_count(iter) - round_up(...);
// Or detect: iter->count = iter->count - shorten/inline
void SAGenTestChecker::checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const {
  if (!BO) return;

  if (BO->getOpcode() == BO_Assign) {
    const Expr *LHS = BO->getLHS();
    const Expr *RHS = BO->getRHS();
    if (!LHS || !RHS) return;

    // Case A: LHS is a variable being assigned a shorten-like computation
    if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        (void)VD; // Silence unused warning; logic is in recordShortenOnAssignIfMatch
        recordShortenOnAssignIfMatch(BO, C);
      }
    }

    // Case B: LHS is iter->count receiving "iter->count - shorten/inline"
    maybeReportOnAssignCountSub(BO, C);
  }
}

void SAGenTestChecker::recordShortenOnAssignIfMatch(const BinaryOperator *BO, CheckerContext &C) const {
  if (!BO || BO->getOpcode() != BO_Assign) return;
  const auto *DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
  if (!DRE) return;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD) return;

  const Expr *RHS = BO->getRHS();
  recordShortenIfMatch(VD, RHS, C);
}

// Detect: iter->count = iter->count - shorten; or iter->count = iter->count - (iov_iter_count(iter) - round_up(...))
void SAGenTestChecker::maybeReportOnAssignCountSub(const BinaryOperator *BO, CheckerContext &C) const {
  if (!BO || BO->getOpcode() != BO_Assign) return;

  const Expr *LHS = BO->getLHS();
  const MemRegion *IterBase = getIterBaseFromCountMember(LHS, C);
  if (!IterBase) return;

  const Expr *RHS = BO->getRHS();
  if (!RHS) return;

  const auto *Sub = dyn_cast<BinaryOperator>(RHS->IgnoreParenImpCasts());
  if (!Sub || Sub->getOpcode() != BO_Sub) return;

  const Expr *SubLHS = Sub->getLHS();
  const Expr *SubRHS = Sub->getRHS();
  if (!SubLHS || !SubRHS) return;

  // Require that the first operand is the same iter->count
  if (!isCountMemberForIterBase(SubLHS, C, IterBase))
    return;

  // Second operand: either recorded var or inline pattern
  const VarDecl *ShortenVD = nullptr;
  bool Matches = isRecordedShortenDeclRefForIter(SubRHS, C, IterBase, ShortenVD);
  if (!Matches)
    Matches = isInlineShortenSubPattern(SubRHS, C, IterBase);

  if (!Matches)
    return;

  if (ShortenVD && hasClampGuardNear(BO, ShortenVD, IterBase, C))
    return;

  reportIssue(BO, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects possible iov_iter->count underflow when subtracting a rounded-up length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
