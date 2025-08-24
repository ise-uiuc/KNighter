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
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required for this checker.

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Off-by-one array access", "Array bounds")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Helper predicates and analyzers
      static const VarDecl *getCanonicalVarDecl(const VarDecl *V) {
        return V ? V->getCanonicalDecl() : nullptr;
      }

      static bool isIntLiteralOne(const Expr *E) {
        if (!E) return false;
        E = E->IgnoreParenImpCasts();
        if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
          return IL->getValue() == 1;
        }
        return false;
      }

      static bool isRefToVar(const Expr *E, const VarDecl *V) {
        if (!E || !V) return false;
        E = E->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            return VD->getCanonicalDecl() == getCanonicalVarDecl(V);
        }
        return false;
      }

      static bool isVarPlusOne(const Expr *E, const VarDecl *V) {
        if (!E || !V) return false;
        E = E->IgnoreParenImpCasts();
        const auto *BO = dyn_cast<BinaryOperator>(E);
        if (!BO) return false;
        if (BO->getOpcode() != BO_Add) return false;
        const Expr *L = BO->getLHS();
        const Expr *R = BO->getRHS();
        if ((isRefToVar(L, V) && isIntLiteralOne(R)) ||
            (isIntLiteralOne(L) && isRefToVar(R, V)))
          return true;
        return false;
      }

      static bool isMinusOneAdjustedExpr(const Expr *E) {
        if (!E) return false;
        E = E->IgnoreParenImpCasts();
        const auto *BO = dyn_cast<BinaryOperator>(E);
        if (!BO) return false;
        if (BO->getOpcode() != BO_Sub) return false;
        return isIntLiteralOne(BO->getRHS());
      }

      static const VarDecl *getInductionVarFromInit(const Stmt *Init) {
        if (!Init) return nullptr;

        if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
          if (!DS->isSingleDecl()) return nullptr;
          const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
          if (!VD) return nullptr;
          if (!VD->getType()->isIntegerType()) return nullptr;
          return getCanonicalVarDecl(VD);
        }

        if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
          if (BO->getOpcode() != BO_Assign) return nullptr;
          const Expr *LHS = BO->getLHS();
          const auto *DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts());
          if (!DRE) return nullptr;
          const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
          if (!VD) return nullptr;
          if (!VD->getType()->isIntegerType()) return nullptr;
          return getCanonicalVarDecl(VD);
        }

        return nullptr;
      }

      static bool isUnitStepIncrement(const Expr *Inc, const VarDecl *V) {
        if (!Inc || !V) return false;
        Inc = Inc->IgnoreParenImpCasts();

        if (const auto *UO = dyn_cast<UnaryOperator>(Inc)) {
          if (UO->isIncrementOp() && isRefToVar(UO->getSubExpr(), V))
            return true;
        }

        if (const auto *CAO = dyn_cast<CompoundAssignOperator>(Inc)) {
          if (CAO->getOpcode() == BO_AddAssign && isRefToVar(CAO->getLHS(), V) &&
              isIntLiteralOne(CAO->getRHS()))
            return true;
        }

        if (const auto *BO = dyn_cast<BinaryOperator>(Inc)) {
          if (BO->getOpcode() == BO_Assign && isRefToVar(BO->getLHS(), V)) {
            const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
            if (const auto *BO2 = dyn_cast<BinaryOperator>(RHS)) {
              if (BO2->getOpcode() == BO_Add) {
                const Expr *L = BO2->getLHS();
                const Expr *R = BO2->getRHS();
                if ((isRefToVar(L, V) && isIntLiteralOne(R)) ||
                    (isRefToVar(R, V) && isIntLiteralOne(L)))
                  return true;
              }
            }
          }
        }

        return false;
      }

      static bool analyzeLoopCondition(const Expr *Cond, const VarDecl *V,
                                       bool &IsStrictUpper, bool &IsMinusOneAdjusted) {
        IsStrictUpper = false;
        IsMinusOneAdjusted = false;

        if (!Cond || !V) return false;
        const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
        if (!BO) return false;

        const Expr *L = BO->getLHS();
        const Expr *R = BO->getRHS();

        switch (BO->getOpcode()) {
        case BO_LT:
          if (isRefToVar(L, V)) {
            IsStrictUpper = true;
            if (isMinusOneAdjustedExpr(R))
              IsMinusOneAdjusted = true;
            return true;
          }
          break;
        case BO_GT:
          if (isRefToVar(R, V)) {
            IsStrictUpper = true;
            if (isMinusOneAdjustedExpr(L))
              IsMinusOneAdjusted = true;
            return true;
          }
          break;
        case BO_LE:
          if (isRefToVar(L, V) && isMinusOneAdjustedExpr(R)) {
            IsStrictUpper = false;
            IsMinusOneAdjusted = true;
            return true;
          }
          break;
        case BO_GE:
          if (isRefToVar(R, V) && isMinusOneAdjustedExpr(L)) {
            IsStrictUpper = false;
            IsMinusOneAdjusted = true;
            return true;
          }
          break;
        default:
          break;
        }
        return false;
      }

      static bool guardInCondition(const Expr *Cond, const VarDecl *V) {
        if (!Cond || !V) return false;
        const Expr *C = Cond->IgnoreParenImpCasts();

        if (const auto *BO = dyn_cast<BinaryOperator>(C)) {
          // Handle logical-AND by searching either side for a valid guard.
          if (BO->getOpcode() == BO_LAnd) {
            return guardInCondition(BO->getLHS(), V) || guardInCondition(BO->getRHS(), V);
          }

          const Expr *L = BO->getLHS();
          const Expr *R = BO->getRHS();
          // i + 1 < X or i + 1 <= X
          if ((BO->getOpcode() == BO_LT || BO->getOpcode() == BO_LE) &&
              (isVarPlusOne(L, V))) {
            return true;
          }
          // i < X - 1 or i <= X - 1
          if ((BO->getOpcode() == BO_LT || BO->getOpcode() == BO_LE) &&
              isRefToVar(L, V) && isMinusOneAdjustedExpr(R)) {
            return true;
          }
        }
        return false;
      }

      static bool hasLocalGuardForASE(ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                      const ForStmt *FS, const VarDecl *V) {
        if (!ASE || !FS || !V) return false;

        llvm::SmallVector<DynTypedNode, 8> Worklist;
        llvm::SmallPtrSet<const void *, 32> Visited;

        Worklist.push_back(DynTypedNode::create<const Stmt>(*ASE));

        while (!Worklist.empty()) {
          DynTypedNode Node = Worklist.pop_back_val();
          auto Parents = Ctx.getParents(Node);
          for (const auto &P : Parents) {
            const Stmt *PS = P.get<Stmt>();
            if (!PS) continue;

            if (Visited.contains(PS))
              continue;
            Visited.insert(PS);

            if (const auto *IFS = dyn_cast<IfStmt>(PS)) {
              const Expr *Cond = IFS->getCond();
              if (guardInCondition(Cond, V))
                return true;
            }

            if (PS == FS)
              continue; // Reached the loop boundary on this path.

            Worklist.push_back(P);
          }
        }

        return false;
      }

      void analyzeForStmt(const ForStmt *FS, ASTContext &Ctx, BugReporter &BR) const {
        if (!FS) return;

        const VarDecl *IVar = getInductionVarFromInit(FS->getInit());
        if (!IVar) return;

        bool IsStrictUpper = false;
        bool IsMinusOneAdjusted = false;
        const Expr *Cond = FS->getCond();
        if (!Cond) return;
        if (!analyzeLoopCondition(Cond, IVar, IsStrictUpper, IsMinusOneAdjusted))
          return;

        // Skip loops that already use (bound - 1).
        if (IsMinusOneAdjusted) return;

        // We only flag loops with strict upper bounds like i < N or N > i.
        if (!IsStrictUpper) return;

        // Ensure unit-step increment on i.
        if (!isUnitStepIncrement(FS->getInc(), IVar))
          return;

        // Traverse the loop body and find a[i + 1]
        struct BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
          const SAGenTestChecker *Checker;
          const ForStmt *FS;
          const VarDecl *IVar;
          ASTContext &Ctx;
          BugReporter &BR;
          const BugType &BT;

          BodyVisitor(const SAGenTestChecker *Checker, const ForStmt *FS,
                      const VarDecl *IVar, ASTContext &Ctx,
                      BugReporter &BR, const BugType &BT)
              : Checker(Checker), FS(FS), IVar(IVar), Ctx(Ctx), BR(BR), BT(BT) {}

          bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
            if (!ASE) return true;
            const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
            // Only consider indices of the form i + 1 or 1 + i.
            if (!Checker->isVarPlusOne(Idx, IVar))
              return true;

            // Check for a local guard like "if (i + 1 < X)" or "if (i < X - 1)".
            if (Checker->hasLocalGuardForASE(Ctx, ASE, FS, IVar))
              return true;

            // Report the potential off-by-one.
            PathDiagnosticLocation ELoc =
                PathDiagnosticLocation::createBegin(ASE, BR.getSourceManager(), nullptr);

            auto R = std::make_unique<BasicBugReport>(
                BT,
                "Possible off-by-one: loop uses i < bound but also accesses a[i + 1]",
                ELoc);
            R->addRange(ASE->getSourceRange());

            // Optionally, highlight the loop condition too.
            if (const Expr *Cond = FS->getCond()) {
              R->addRange(Cond->getSourceRange());
            }

            BR.emitReport(std::move(R));
            return true;
          }
        };

        BodyVisitor V(this, FS, IVar, Ctx, BR, *BT);
        if (const Stmt *Body = FS->getBody())
          V.TraverseStmt(const_cast<Stmt *>(Body));
      }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const Stmt *Body = D->getBody();
  if (!Body) return;

  // Visit all ForStmt nodes and analyze them.
  struct TopVisitor : public RecursiveASTVisitor<TopVisitor> {
    const SAGenTestChecker *Checker;
    ASTContext &Ctx;
    BugReporter &BR;

    TopVisitor(const SAGenTestChecker *Checker, ASTContext &Ctx, BugReporter &BR)
        : Checker(Checker), Ctx(Ctx), BR(BR) {}

    bool VisitForStmt(ForStmt *FS) {
      Checker->analyzeForStmt(FS, Ctx, BR);
      return true;
    }
  };

  TopVisitor TV(this, Mgr.getASTContext(), BR);
  TV.TraverseStmt(const_cast<Stmt *>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one array access in loops (i < N with a[i + 1])",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
