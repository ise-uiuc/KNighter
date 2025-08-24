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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "I/O iterator underflow", "Logic")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isIovIterCountFieldRegion(const MemRegion *MR);
      static bool isIovIterCountMemberExpr(const Expr *E);
      static bool looksLikeIovIterCount(const Expr *E, CheckerContext &C);
      static bool looksLikeRoundUp(const Expr *E, CheckerContext &C);
      static bool refersToVar(const Expr *E, const VarDecl *VD);
      static bool isZeroExpr(const Expr *E, CheckerContext &C);

      // Find last RHS expression that defines VD before 'Before' within 'CS'.
      static const Expr* findLastDefRHSForVarBefore(const VarDecl *VD,
                                                    const CompoundStmt *CS,
                                                    const Stmt *Before,
                                                    const Stmt *&DefStmt);

      // Search guards between From (exclusive) and To (exclusive) in CS.
      static bool guardedByShortenCheck(const CompoundStmt *CS,
                                        const Stmt *From, const Stmt *To,
                                        const VarDecl *VD, CheckerContext &C);

      static bool condChecksShortenVsIterCount(const Expr *Cond,
                                               const VarDecl *VD,
                                               CheckerContext &C);

      static bool branchAssignsVarZero(const Stmt *Body, const VarDecl *VD,
                                       CheckerContext &C);
};

// --------- Helper implementations ---------

static const Expr* ignoreCastsAndParens(const Expr *E) {
  if (!E) return nullptr;
  return E->IgnoreParenImpCasts();
}

bool SAGenTestChecker::isIovIterCountFieldRegion(const MemRegion *MR) {
  if (!MR) return false;
  MR = MR->getBaseRegion();
  const FieldRegion *FR = dyn_cast<FieldRegion>(MR);
  if (!FR) return false;

  const FieldDecl *FD = FR->getDecl();
  if (!FD) return false;
  if (FD->getName() != "count") return false;

  const RecordDecl *RD = FD->getParent();
  if (!RD) return false;
  // 'struct iov_iter'
  if (RD->getName() == "iov_iter")
    return true;

  return false;
}

bool SAGenTestChecker::isIovIterCountMemberExpr(const Expr *E) {
  if (!E) return false;
  E = ignoreCastsAndParens(E);
  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if (!ME) return false;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD) return false;
  if (VD->getName() != "count")
    return false;

  // Try to confirm the base is an iov_iter
  const FieldDecl *FD = dyn_cast<FieldDecl>(VD);
  if (!FD) return false;
  const RecordDecl *RD = FD->getParent();
  if (!RD) return false;
  return RD->getName() == "iov_iter";
}

bool SAGenTestChecker::looksLikeIovIterCount(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = ignoreCastsAndParens(E);

  if (isIovIterCountMemberExpr(E))
    return true;

  // iov_iter_count(iter)
  if (ExprHasName(E, "iov_iter_count", C))
    return true;

  return false;
}

bool SAGenTestChecker::looksLikeRoundUp(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = ignoreCastsAndParens(E);

  // If a direct call expression with callee id
  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef Name = FD->getIdentifier() ? FD->getName() : "";
      if (Name == "round_up" || Name == "roundup" || Name == "ALIGN")
        return true;
    }
  }

  // Fallback: textual name (handles macros)
  if (ExprHasName(E, "round_up", C) || ExprHasName(E, "roundup", C) ||
      ExprHasName(E, "ALIGN", C))
    return true;

  return false;
}

bool SAGenTestChecker::refersToVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD) return false;
  E = ignoreCastsAndParens(E);

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }

  // Recurse into binary/unary/conditional etc.
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast_or_null<Expr>(Child)) {
      if (refersToVar(CE, VD)) return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isZeroExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = ignoreCastsAndParens(E);

  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    return IL->getValue() == 0;
  }

  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C))
    return Val == 0;

  return false;
}

const Expr* SAGenTestChecker::findLastDefRHSForVarBefore(const VarDecl *VD,
                                                         const CompoundStmt *CS,
                                                         const Stmt *Before,
                                                         const Stmt *&DefStmt) {
  if (!VD || !CS || !Before) return nullptr;
  const Expr *LastRHS = nullptr;
  DefStmt = nullptr;

  for (const Stmt *S : CS->body()) {
    if (S == Before)
      break;

    // Handle DeclStmt: "size_t shorten = expr;"
    if (const auto *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        if (const auto *Var = dyn_cast<VarDecl>(D)) {
          if (Var == VD && Var->hasInit()) {
            LastRHS = Var->getInit();
            DefStmt = DS;
          }
        }
      }
    }

    // Handle simple assignment: "shorten = expr;"
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Assign) {
        const Expr *LHS = ignoreCastsAndParens(BO->getLHS());
        if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (DRE->getDecl() == VD) {
            LastRHS = BO->getRHS();
            DefStmt = BO;
          }
        }
      }
    }
  }

  return LastRHS;
}

bool SAGenTestChecker::branchAssignsVarZero(const Stmt *Body,
                                            const VarDecl *VD,
                                            CheckerContext &C) {
  if (!Body || !VD) return false;

  // Walk the subtree to find "VD = 0;"
  if (const auto *BO = dyn_cast<BinaryOperator>(Body)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = ignoreCastsAndParens(BO->getLHS());
      const Expr *RHS = ignoreCastsAndParens(BO->getRHS());
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == VD && isZeroExpr(RHS, C))
          return true;
      }
    }
  }

  for (const Stmt *Child : Body->children()) {
    if (!Child) continue;
    if (branchAssignsVarZero(Child, VD, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::condChecksShortenVsIterCount(const Expr *Cond,
                                                    const VarDecl *VD,
                                                    CheckerContext &C) {
  if (!Cond) return false;
  Cond = ignoreCastsAndParens(Cond);

  // Look for comparison with >= or >
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_GE || Op == BO_GT) {
      const Expr *L = ignoreCastsAndParens(BO->getLHS());
      const Expr *R = ignoreCastsAndParens(BO->getRHS());

      bool LeftIsShorten = refersToVar(L, VD);
      bool RightIsShorten = refersToVar(R, VD);
      bool LeftIsIterLen = looksLikeIovIterCount(L, C);
      bool RightIsIterLen = looksLikeIovIterCount(R, C);

      // shorten >= iter->count   OR   iter->count <= shorten (same meaning)
      if ((LeftIsShorten && RightIsIterLen) || (RightIsShorten && LeftIsIterLen))
        return true;
    }
  }

  // Fallback textual guard in condition (coarse)
  if (ExprHasName(Cond, VD->getName(), C) &&
      (ExprHasName(Cond, "iov_iter_count", C) || ExprHasName(Cond, "count", C))) {
    return true;
  }

  return false;
}

bool SAGenTestChecker::guardedByShortenCheck(const CompoundStmt *CS,
                                             const Stmt *From, const Stmt *To,
                                             const VarDecl *VD,
                                             CheckerContext &C) {
  if (!CS || !To || !VD) return false;

  bool InRange = (From == nullptr);
  for (const Stmt *S : CS->body()) {
    if (!InRange) {
      if (S == From) InRange = true;
      continue;
    }
    if (S == To)
      break;

    if (const auto *IfS = dyn_cast<IfStmt>(S)) {
      const Expr *Cond = IfS->getCond();
      if (condChecksShortenVsIterCount(Cond, VD, C)) {
        // Check if then-branch assigns VD to 0 (like: shorten = 0;)
        if (const Stmt *Then = IfS->getThen()) {
          if (branchAssignsVarZero(Then, VD, C))
            return true;
        }
      }
    }
  }
  return false;
}

// --------- Main logic ---------

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // We target writes to iter->count (struct iov_iter::count)
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!isIovIterCountFieldRegion(MR))
    return;

  if (!S) return;

  const CompoundAssignOperator *CAO = dyn_cast<CompoundAssignOperator>(S);
  const BinaryOperator *BOAssign = dyn_cast<BinaryOperator>(S);

  const Expr *ShrinkExpr = nullptr;
  const Stmt *DefStmt = nullptr;
  const BinaryOperator *Diff = nullptr;

  // Case 1: iter->count -= X;
  if (CAO && CAO->getOpcode() == BO_SubAssign) {
    // We only analyze pattern when LHS is iter->count; Loc already ensures that.
    ShrinkExpr = CAO->getRHS();
  }
  // Case 2: iter->count = iter->count - X; or count = something;
  else if (BOAssign && BOAssign->getOpcode() == BO_Assign) {
    // LHS should be iter->count; the Loc filter ensures this.
    const Expr *RHS = BOAssign->getRHS();
    if (!RHS) return;
    RHS = ignoreCastsAndParens(RHS);
    if (const auto *BOsub = dyn_cast<BinaryOperator>(RHS)) {
      if (BOsub->getOpcode() == BO_Sub) {
        // Recognize "iter->count = iter->count - shrink"
        // Then shrink is the other side, but we actually need shrink itself only if used as A-B separately.
        // However, our pattern focuses on shrink being computed as A-B. This assignment form is less common.
        // We'll treat RHS entirely later only if it matches A - B directly.
        Diff = BOsub;
      }
    } else {
      // Maybe "iter->count = iter->count - shorten" wasn't parsed as BinaryOperator at this level.
      // Or simply "iter->count = count - shorten;" not our primary target.
      return;
    }
  } else {
    return;
  }

  const Expr *DiffExpr = nullptr;

  // If ShrinkExpr is a variable, find its definition as A - B
  if (ShrinkExpr) {
    ShrinkExpr = ignoreCastsAndParens(ShrinkExpr);
    if (const auto *DRE = dyn_cast<DeclRefExpr>(ShrinkExpr)) {
      const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (!VD) return;

      // Find the containing CompoundStmt
      const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(S, C);
      const Expr *DefRHS = findLastDefRHSForVarBefore(VD, CS, S, DefStmt);
      if (!DefRHS) return;

      DefRHS = ignoreCastsAndParens(DefRHS);
      if (const auto *BOsub = dyn_cast<BinaryOperator>(DefRHS)) {
        if (BOsub->getOpcode() != BO_Sub)
          return;
        DiffExpr = BOsub;

        // Try to detect whether there's a guard like:
        // if (shorten >= iter->count) shorten = 0;
        if (guardedByShortenCheck(CS, DefStmt, S, VD, C)) {
          return; // Properly guarded; do not warn.
        }
      } else {
        return;
      }
    } else if (const auto *BOsub = dyn_cast<BinaryOperator>(ShrinkExpr)) {
      if (BOsub->getOpcode() != BO_Sub)
        return;
      DiffExpr = BOsub;
    } else {
      return;
    }
  } else if (Diff) {
    DiffExpr = Diff;
  }

  if (!DiffExpr)
    return;

  // Ensure it's an unsigned 'A - B' style computation.
  QualType T = DiffExpr->getType();
  if (!T->isUnsignedIntegerType())
    return;

  const auto *BOsub = dyn_cast<BinaryOperator>(DiffExpr);
  if (!BOsub || BOsub->getOpcode() != BO_Sub)
    return;

  const Expr *A = ignoreCastsAndParens(BOsub->getLHS());
  const Expr *B = ignoreCastsAndParens(BOsub->getRHS());
  if (!A || !B) return;

  // Heuristic recognition of A (current length) and B (aligned length)
  bool AisLen = looksLikeIovIterCount(A, C) || isIovIterCountMemberExpr(A);
  bool BisAligned = looksLikeRoundUp(B, C);
  if (!(AisLen && BisAligned)) {
    // Try the opposite (be conservative)
    bool AisAligned = looksLikeRoundUp(A, C);
    bool BisLen = looksLikeIovIterCount(B, C) || isIovIterCountMemberExpr(B);
    if (!(AisAligned && BisLen)) {
      return; // Not the pattern we look for
    } else {
      // If it's aligned - len, then it's not our "shrink = len - aligned" idiom.
      // This is not the underflow pattern we're targeting.
      return;
    }
  }

  // Optional constant pruning: if we can prove A >= B at compile-time, skip.
  llvm::APSInt Aval, Bval;
  if (EvaluateExprToInt(Aval, A, C) && EvaluateExprToInt(Bval, B, C)) {
    if (Aval >= Bval)
      return;
  }

  // Report a potential underflow
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential underflow of iter->count when shrinking by aligned length", N);
  R->addRange(S->getSourceRange());

  // If we have a defining statement like "shorten = A - round_up(...);", point to it.
  if (DefStmt) {
    PathDiagnosticLocation DefLoc = PathDiagnosticLocation::createBegin(DefStmt, C.getSourceManager(), C.getLocationContext());
    R->addNote("shrink amount computed here", DefLoc);
  }

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects underflow when shrinking iov_iter->count by aligned length without guard",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
