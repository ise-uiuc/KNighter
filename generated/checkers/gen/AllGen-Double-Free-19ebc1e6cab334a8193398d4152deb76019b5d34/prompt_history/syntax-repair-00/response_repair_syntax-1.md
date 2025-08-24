```cpp
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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

 // If necessary

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free on retry", "Memory Management")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Helper data structures
      enum class WriteKind { NullInit, AllocWrite, OtherWrite };

      struct LabelInfo {
        const LabelDecl *LD = nullptr;
        std::string Name;
        SourceLocation Loc;
      };

      struct GotoInfo {
        const LabelDecl *Target = nullptr;
        SourceLocation Loc;
      };

      struct FreeEvent {
        const VarDecl *Var = nullptr;
        std::string Callee;
        SourceLocation Loc;
      };

      struct WriteEvent {
        const VarDecl *Var = nullptr;
        WriteKind Kind = WriteKind::OtherWrite;
        SourceLocation Loc;
      };

      // Visitor to collect events
      class BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
      public:
        BodyVisitor(ASTContext &Ctx,
                    std::vector<LabelInfo> &Labels,
                    std::vector<GotoInfo> &Gotos,
                    std::vector<FreeEvent> &Frees,
                    std::vector<WriteEvent> &Writes)
            : Ctx(Ctx), Labels(Labels), Gotos(Gotos), Frees(Frees), Writes(Writes) {}

        bool VisitLabelStmt(LabelStmt *S) {
          LabelInfo LI;
          LI.LD = S->getDecl();
          if (LI.LD)
            LI.Name = LI.LD->getName().str();
          LI.Loc = S->getBeginLoc();
          Labels.push_back(LI);
          return true;
        }

        bool VisitGotoStmt(GotoStmt *S) {
          GotoInfo GI;
          GI.Target = S->getLabel();
          GI.Loc = S->getGotoLoc();
          Gotos.push_back(GI);
          return true;
        }

        bool VisitCallExpr(CallExpr *E) {
          const FunctionDecl *FD = E->getDirectCallee();
          if (!FD) return true;

          StringRef Name = FD->getName();
          if (isFreeLike(Name)) {
            if (E->getNumArgs() >= 1) {
              const Expr *Arg0 = E->getArg(0);
              Arg0 = Arg0 ? Arg0->IgnoreParenImpCasts() : nullptr;
              if (const auto *DRE = dyn_cast_or_null<DeclRefExpr>(Arg0)) {
                if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                  if (VD->getType()->isPointerType()) {
                    FreeEvent FE;
                    FE.Var = VD;
                    FE.Callee = Name.str();
                    FE.Loc = E->getExprLoc();
                    Frees.push_back(FE);
                  }
                }
              }
            }
          }
          return true;
        }

        bool VisitBinaryOperator(BinaryOperator *BO) {
          if (!BO->isAssignmentOp())
            return true;

          const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
          const Expr *RHS = BO->getRHS();

          const auto *LHS_DRE = dyn_cast<DeclRefExpr>(LHS);
          if (!LHS_DRE) return true;

          const auto *VD = dyn_cast<VarDecl>(LHS_DRE->getDecl());
          if (!VD) return true;
          if (!VD->getType()->isPointerType()) return true;

          WriteEvent WE;
          WE.Var = VD;
          WE.Loc = BO->getOperatorLoc();
          WE.Kind = classifyWrite(RHS);
          Writes.push_back(WE);
          return true;
        }

        bool VisitDeclStmt(DeclStmt *DS) {
          if (!DS->isSingleDecl())
            return true;

          const Decl *D = DS->getSingleDecl();
          const auto *VD = dyn_cast<VarDecl>(D);
          if (!VD) return true;
          if (!VD->getType()->isPointerType()) return true;

          if (const Expr *Init = VD->getInit()) {
            WriteEvent WE;
            WE.Var = VD;
            WE.Loc = Init->getExprLoc();
            WE.Kind = classifyWrite(Init);
            Writes.push_back(WE);
          }
          return true;
        }

      private:
        ASTContext &Ctx;
        std::vector<LabelInfo> &Labels;
        std::vector<GotoInfo> &Gotos;
        std::vector<FreeEvent> &Frees;
        std::vector<WriteEvent> &Writes;

        static bool isFreeLike(StringRef Name) {
          return Name == "kfree" || Name == "kvfree" || Name == "vfree" ||
                 Name == "kfree_sensitive";
        }

        static bool isAllocLike(StringRef Name) {
          return Name == "kmalloc" || Name == "kzalloc" || Name == "kcalloc" ||
                 Name == "kvzalloc" || Name == "vzalloc" || Name == "kmalloc_array" ||
                 Name == "kstrdup" || Name == "krealloc";
        }

        WriteKind classifyWrite(const Expr *RHS) {
          if (!RHS) return WriteKind::OtherWrite;

          // Null detection
          if (RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull))
            return WriteKind::NullInit;

          // Zero literal (covers cases where null macro didn't fold)
          if (const auto *IL = dyn_cast<IntegerLiteral>(RHS->IgnoreParenCasts())) {
            if (IL->getValue() == 0)
              return WriteKind::NullInit;
          }

          // Alloc-like calls
          if (const auto *CE = dyn_cast<CallExpr>(RHS->IgnoreParenCasts())) {
            const FunctionDecl *FD = CE->getDirectCallee();
            if (FD) {
              StringRef Name = FD->getName();
              if (isAllocLike(Name))
                return WriteKind::AllocWrite;
            }
          }

          return WriteKind::OtherWrite;
        }
      }; // end BodyVisitor

      // Helper utilities
      static SourceLocation expLoc(const SourceManager &SM, SourceLocation L) {
        return SM.getExpansionLoc(L);
      }

      static bool before(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        A = expLoc(SM, A);
        B = expLoc(SM, B);
        return SM.isBeforeInTranslationUnit(A, B);
      }

      static bool equalLoc(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        A = expLoc(SM, A);
        B = expLoc(SM, B);
        return A == B;
      }

      static bool lessOrEqual(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        return before(SM, A, B) || equalLoc(SM, A, B);
      }

      static const LabelDecl *nearestCleanupBefore(const SourceManager &SM,
                                                   const std::vector<LabelInfo> &Labels,
                                                   const std::set<const LabelDecl*> &CleanupLabels,
                                                   SourceLocation Loc) {
        const LabelDecl *Best = nullptr;
        SourceLocation BestLoc;
        for (const auto &L : Labels) {
          if (!CleanupLabels.count(L.LD))
            continue;
          if (lessOrEqual(SM, L.Loc, Loc)) {
            if (!Best || before(SM, BestLoc, L.Loc)) {
              Best = L.LD;
              BestLoc = L.Loc;
            }
          }
        }
        return Best;
      }

      static bool hasAllocBefore(const SourceManager &SM,
                                 const std::vector<WriteEvent> &Writes,
                                 const VarDecl *V,
                                 SourceLocation Loc) {
        for (const auto &W : Writes) {
          if (W.Var == V && W.Kind == WriteKind::AllocWrite && before(SM, W.Loc, Loc))
            return true;
        }
        return false;
      }

      static SourceLocation getLabelLoc(const std::vector<LabelInfo> &Labels,
                                        const LabelDecl *LD) {
        for (const auto &L : Labels)
          if (L.LD == LD) return L.Loc;
        return SourceLocation();
      }

      static bool isNullInitBetween(const SourceManager &SM,
                                    const std::vector<WriteEvent> &Writes,
                                    const VarDecl *V,
                                    SourceLocation StartExclusive,
                                    SourceLocation EndExclusive) {
        for (const auto &W : Writes) {
          if (W.Var != V) continue;
          if (W.Kind != WriteKind::NullInit) continue;
          if (before(SM, StartExclusive, W.Loc) && before(SM, W.Loc, EndExclusive))
            return true;
        }
        return false;
      }

      static bool writeAfter(const SourceManager &SM,
                             const WriteEvent &A,
                             const WriteEvent &B) {
        return before(SM, B.Loc, A.Loc);
      }

      static SourceLocation firstWriteAfter(const SourceManager &SM,
                                            const std::vector<WriteEvent> &Writes,
                                            const VarDecl *V,
                                            SourceLocation LocR,
                                            bool &Found) {
        Found = false;
        SourceLocation Best;
        for (const auto &W : Writes) {
          if (W.Var != V) continue;
          if (before(SM, LocR, W.Loc)) {
            if (!Found || before(SM, W.Loc, Best)) {
              Best = W.Loc;
              Found = true;
            }
          }
        }
        return Best;
      }

}; // end class

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return;
  const Stmt *Body = FD->getBody();
  if (!Body) return;

  ASTContext &ACtx = Mgr.getASTContext();
  const SourceManager &SM = Mgr.getSourceManager();

  std::vector<LabelInfo> Labels;
  std::vector<GotoInfo> Gotos;
  std::vector<FreeEvent> Frees;
  std::vector<WriteEvent> Writes;

  BodyVisitor V(ACtx, Labels, Gotos, Frees, Writes);
  V.TraverseStmt(const_cast<Stmt *>(Body));

  // Classify labels as cleanup or retry via goto directions
  std::set<const LabelDecl*> CleanupLabels;
  std::set<const LabelDecl*> RetryLabels;
  std::map<const LabelDecl*, std::vector<SourceLocation>> GotoLocsByLabel;

  for (const auto &G : Gotos) {
    if (!G.Target) continue;
    SourceLocation LLoc = getLabelLoc(Labels, G.Target);
    if (LLoc.isInvalid()) continue;

    GotoLocsByLabel[G.Target].push_back(G.Loc);

    if (before(SM, G.Loc, LLoc)) {
      CleanupLabels.insert(G.Target); // forward goto to label => cleanup
    } else if (before(SM, LLoc, G.Loc)) {
      RetryLabels.insert(G.Target);   // backward goto => retry
    }
  }

  // Map each free to the nearest preceding cleanup label if any and require prior alloc
  struct FreedInCleanup {
    const VarDecl *Var = nullptr;
    const LabelDecl *Cleanup = nullptr;
    SourceLocation FreeLoc;
  };
  std::vector<FreedInCleanup> FreedList;
  for (const auto &F : Frees) {
    if (!F.Var) continue;
    const LabelDecl *C = nearestCleanupBefore(SM, Labels, CleanupLabels, F.Loc);
    if (!C) continue;
    if (!hasAllocBefore(SM, Writes, F.Var, F.Loc))
      continue;
    FreedList.push_back({F.Var, C, F.Loc});
  }

  // For each freed var in cleanup, and each retry label reachable after free, check missing NULL reinit
  std::set<std::pair<const VarDecl*, const LabelDecl*>> Reported; // (Var, RetryLabel)
  for (const auto &FI : FreedList) {
    // Consider retry labels R such that there is a goto to R after FI.FreeLoc
    for (const LabelDecl *R : RetryLabels) {
      auto It = GotoLocsByLabel.find(R);
      if (It == GotoLocsByLabel.end()) continue;

      // Any goto to R after free?
      bool HasBackwardGotoAfterFree = false;
      for (const auto &GLoc : It->second) {
        if (before(SM, FI.FreeLoc, GLoc)) {
          HasBackwardGotoAfterFree = true;
          break;
        }
      }
      if (!HasBackwardGotoAfterFree) continue;

      // Now ensure there's a goto to cleanup C between R and first write of Var after R
      SourceLocation RLoc = getLabelLoc(Labels, R);
      if (RLoc.isInvalid()) continue;

      bool FoundFirstWrite = false;
      SourceLocation FirstWLoc = firstWriteAfter(SM, Writes, FI.Var, RLoc, FoundFirstWrite);

      // Iterate gotos to the cleanup label C, and check those between RLoc and FirstWLoc (or any after R if no write)
      auto ItC = GotoLocsByLabel.find(FI.Cleanup);
      if (ItC == GotoLocsByLabel.end()) continue;

      // Find the first offending goto (no NULL init between R and Goto)
      SourceLocation OffendingGoto;
      for (const auto &GLoc : ItC->second) {
        if (!before(SM, RLoc, GLoc))
          continue; // must be after retry label
        if (FoundFirstWrite && !before(SM, GLoc, FirstWLoc))
          continue; // must be before the first write after R

        // Is there a NullInit write for Var between RLoc and GLoc?
        if (!isNullInitBetween(SM, Writes, FI.Var, RLoc, GLoc)) {
          OffendingGoto = GLoc;
          break;
        }
      }

      if (OffendingGoto.isInvalid())
        continue;

      // Deduplicate (Var, RetryLabel)
      auto Key = std::make_pair(FI.Var, R);
      if (Reported.count(Key))
        continue;
      Reported.insert(Key);

      // Report
      PathDiagnosticLocation ELoc(OffendingGoto, BR.getSourceManager());
      auto Rpt = std::make_unique<BasicBugReport>(
          *BT, "Pointer freed in cleanup is not reset to NULL on retry", ELoc);
      // Provide context
      std::string Msg = "Possible double free: '";
      Msg += FI.Var->getName().str();
      Msg += "' is freed in cleanup and not set to NULL before goto to cleanup on retry.";
      Rpt->setDeclWithIssue(FD);
      Rpt->addNote(Msg, ELoc);

      // Add note for free site
      PathDiagnosticLocation FreeLoc(FI.FreeLoc, BR.getSourceManager());
      Rpt->addNote("Freed here in cleanup", FreeLoc);

      BR.emitReport(std::move(Rpt));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing pointer NULL reinitialization at retry labels leading to double free in cleanup",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
