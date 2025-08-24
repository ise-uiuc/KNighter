Refinement Plan:
- Root cause: The checker treats any backward goto after a cleanup free as a retry candidate, even when that goto is unreachable from the cleanup (e.g., because of an intervening return), and it also unconditionally flags when no post-restart assignment is found. This leads to false positives like the isofs case.
- Fixes:
  1. Require CFG reachability from the cleanup free to the backward goto to consider it a true retry edge. This filters out cases where a return or unconditional exit makes the backward goto unreachable from the cleanup.
  2. Only warn if there exists at least one “early goto to cleanup” after the restart label and before the first reassignment. Remove the incorrect unconditional flagging when no reassignment is found; instead, require an actual early goto to cleanup in that region and that it is reachable from the restart label in the CFG.
  3. Keep existing checks that avoid self-jumps to the cleanup label and that look for a reset-to-NULL between the free and the retry goto.
- Edge cases and regressions:
  - The new CFG reachability checks avoid false positives in functions that have structured cleanups with immediate returns after free.
  - For the target buggy code (smb2_set_ea), both reachability conditions are satisfied: the retry goto is directly after cleanup and reachable; there are early gotos to the cleanup before re-allocation; no NULL reset occurs. The checker will continue to flag it.
  - If CFG indexing fails (should be rare), the checker will conservatively avoid reporting to prevent false positives.
- API compatibility: Uses Clang-18 APIs (CFG via AnalysisDeclContext). Does not remove any existing include; adds necessary includes for CFG and maps.

Refined Code:
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
#include "clang/AST/Decl.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallVector.h"
#include <vector>
#include <utility>
#include <memory"

// Added includes for CFG-based reachability (Clang-18 compatible).
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/DenseMap.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

struct LabelInfo {
  const LabelStmt *LStmt = nullptr;
  const LabelDecl *LDecl = nullptr;
  SourceLocation Loc;
};

struct GotoInfo {
  const GotoStmt *G = nullptr;
  const LabelDecl *Target = nullptr;
  SourceLocation Loc;
};

struct FreeSite {
  const VarDecl *P = nullptr;                 // pointer variable freed
  const LabelDecl *CleanupLabel = nullptr;    // label where free occurs
  const CallExpr *FreeCall = nullptr;         // kfree/kvfree call
  SourceLocation FreeLoc;
};

struct AssignInfo {
  const VarDecl *P = nullptr;
  SourceLocation Loc;
  bool ResetToNull = false;
};

class BodyScanner : public RecursiveASTVisitor<BodyScanner> {
public:
  BodyScanner(ASTContext &Ctx,
              std::vector<LabelInfo> &Labels,
              std::vector<GotoInfo> &Gotos,
              std::vector<FreeSite> &Frees,
              std::vector<AssignInfo> &Assigns)
      : Ctx(Ctx), SM(Ctx.getSourceManager()), Labels(Labels), Gotos(Gotos),
        Frees(Frees), Assigns(Assigns) {}

  bool VisitLabelStmt(LabelStmt *L) {
    LabelInfo Info;
    Info.LStmt = L;
    Info.LDecl = L->getDecl();
    Info.Loc = getExpansionLocSafe(L->getBeginLoc());
    Labels.push_back(Info);

    // Scan the sub-statement for free-like calls.
    if (Stmt *Sub = L->getSubStmt())
      collectFreesUnder(Sub, L->getDecl());

    return true;
  }

  bool VisitGotoStmt(GotoStmt *G) {
    GotoInfo GI;
    GI.G = G;
    GI.Target = G->getLabel();
    GI.Loc = getExpansionLocSafe(G->getGotoLoc());
    Gotos.push_back(GI);
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO->isAssignmentOp())
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS();

    const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return true;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return true;

    if (!VD->getType()->isAnyPointerType())
      return true;

    bool IsNull = isNullPointerExpr(RHS);
    AssignInfo AI;
    AI.P = VD;
    AI.Loc = getExpansionLocSafe(BO->getExprLoc());
    AI.ResetToNull = IsNull;
    Assigns.push_back(AI);
    return true;
  }

  bool VisitDeclStmt(DeclStmt *DS) {
    for (auto *D : DS->decls()) {
      auto *VD = dyn_cast<VarDecl>(D);
      if (!VD)
        continue;
      if (!VD->getType()->isAnyPointerType())
        continue;
      if (!VD->hasInit())
        continue;

      const Expr *Init = VD->getInit();
      bool IsNull = isNullPointerExpr(Init);
      AssignInfo AI;
      AI.P = VD;
      AI.Loc = getExpansionLocSafe(VD->getLocation());
      AI.ResetToNull = IsNull;
      Assigns.push_back(AI);
    }
    return true;
  }

private:
  ASTContext &Ctx;
  const SourceManager &SM;
  std::vector<LabelInfo> &Labels;
  std::vector<GotoInfo> &Gotos;
  std::vector<FreeSite> &Frees;
  std::vector<AssignInfo> &Assigns;

  SourceLocation getExpansionLocSafe(SourceLocation L) const {
    if (L.isInvalid())
      return L;
    return SM.getExpansionLoc(L);
  }

  static bool isFreeName(StringRef N) {
    return N == "kfree" || N == "kvfree";
  }

  bool isNullPointerExpr(const Expr *E) const {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull) !=
           Expr::NPCK_NotNull;
  }

  bool isFreeCallOnVar(const CallExpr *CE, const VarDecl *&OutVD) const {
    OutVD = nullptr;
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return false;
    const IdentifierInfo *II = FD->getIdentifier();
    if (!II)
      return false;
    if (!isFreeName(II->getName()))
      return false;

    if (CE->getNumArgs() < 1)
      return false;

    const Expr *Arg0 = CE->getArg(0)->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg0)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->getType()->isAnyPointerType()) {
          OutVD = VD;
          return true;
        }
      }
    }
    return false;
  }

  void collectFreesUnder(Stmt *S, const LabelDecl *Where) {
    if (!S)
      return;

    struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
      LocalVisitor(const BodyScanner &Outer, const LabelDecl *L,
                   std::vector<FreeSite> &Frees)
          : Outer(Outer), LDecl(L), Frees(Frees) {}

      bool VisitCallExpr(CallExpr *CE) {
        const VarDecl *VD = nullptr;
        if (Outer.isFreeCallOnVar(CE, VD) && VD) {
          FreeSite FS;
          FS.P = VD;
          FS.CleanupLabel = LDecl;
          FS.FreeCall = CE;
          FS.FreeLoc = Outer.getExpansionLocSafe(CE->getExprLoc());
          Frees.push_back(FS);
        }
        return true;
      }

      const BodyScanner &Outer;
      const LabelDecl *LDecl;
      std::vector<FreeSite> &Frees;
    };

    LocalVisitor LV(*this, Where, Frees);
    LV.TraverseStmt(S);
  }
};

// CFG statement index for reachability and within-block ordering.
struct CFGPos {
  const CFGBlock *Block = nullptr;
  unsigned Index = 0; // index of CFGElement within the block
};

struct CFGStmtIndex {
  llvm::DenseMap<const Stmt *, llvm::SmallVector<CFGPos, 2>> Map;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker()
        : BT(new BugType(this, "Possible double free across retry loop", "Memory Error")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:
      static SourceLocation getExpansionLocSafe(const SourceManager &SM, SourceLocation L) {
        if (L.isInvalid())
          return L;
        return SM.getExpansionLoc(L);
      }

      static bool before(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        A = getExpansionLocSafe(SM, A);
        B = getExpansionLocSafe(SM, B);
        return SM.isBeforeInTranslationUnit(A, B);
      }

      static bool strictlyBetween(const SourceManager &SM, SourceLocation X,
                                  SourceLocation L, SourceLocation R) {
        return before(SM, L, X) && before(SM, X, R);
      }

      static bool isSelfCleanupJump(const GotoInfo &GR, const FreeSite &FS) {
        // A restart candidate must not be a goto back to the same cleanup label.
        return GR.Target && FS.CleanupLabel && (GR.Target == FS.CleanupLabel);
      }

      static void buildCFGStmtIndex(const CFG *Cfg, CFGStmtIndex &Index) {
        if (!Cfg) return;
        for (const CFGBlock *B : *Cfg) {
          unsigned I = 0;
          for (auto EI = B->begin(); EI != B->end(); ++EI, ++I) {
            if (auto CS = EI->getAs<CFGStmt>()) {
              const Stmt *S = CS->getStmt();
              Index.Map[S].push_back({B, I});
            }
          }
        }
      }

      // Returns true if there's a CFG path from any occurrence of 'From' to any occurrence of 'To'.
      static bool cfgReachable(const CFG *Cfg, const CFGStmtIndex &Index,
                               const Stmt *From, const Stmt *To) {
        if (!Cfg || !From || !To)
          return false;

        auto FI = Index.Map.find(From);
        auto TI = Index.Map.find(To);
        if (FI == Index.Map.end() || TI == Index.Map.end())
          return false;

        for (const CFGPos &FPos : FI->second) {
          for (const CFGPos &TPos : TI->second) {
            if (FPos.Block == TPos.Block) {
              if (FPos.Index <= TPos.Index)
                return true;
              // Otherwise, same block but To occurs before From; not reachable in-order.
              continue;
            }

            // BFS over blocks from FPos.Block to TPos.Block
            llvm::BitVector Visited(Cfg->getNumBlockIDs());
            llvm::SmallVector<const CFGBlock *, 16> WL;
            WL.push_back(FPos.Block);
            Visited.set(FPos.Block->getBlockID());
            while (!WL.empty()) {
              const CFGBlock *B = WL.back();
              WL.pop_back();
              for (const CFGBlock *Succ : *B) {
                if (!Succ)
                  continue;
                if (Visited.test(Succ->getBlockID()))
                  continue;
                Visited.set(Succ->getBlockID());
                if (Succ == TPos.Block)
                  return true;
                WL.push_back(Succ);
              }
            }
          }
        }

        return false;
      }

      static const Stmt *getFirstStmtAfterLabel(const std::vector<LabelInfo> &Labels,
                                                const LabelDecl *LD) {
        for (const auto &LI : Labels) {
          if (LI.LDecl == LD) {
            if (const LabelStmt *LS = LI.LStmt) {
              return LS->getSubStmt();
            }
          }
        }
        return nullptr;
      }

      void detectAndReport(const FunctionDecl *FD,
                           const std::vector<LabelInfo> &Labels,
                           const std::vector<GotoInfo> &Gotos,
                           const std::vector<FreeSite> &Frees,
                           const std::vector<AssignInfo> &Assigns,
                           const CFG *Cfg, const CFGStmtIndex &CfgIndex,
                           BugReporter &BR, ASTContext &AC) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  std::vector<LabelInfo> Labels;
  std::vector<GotoInfo> Gotos;
  std::vector<FreeSite> Frees;
  std::vector<AssignInfo> Assigns;

  BodyScanner Scanner(Ctx, Labels, Gotos, Frees, Assigns);
  Scanner.TraverseStmt(const_cast<Stmt *>(Body));

  // Build CFG and index for reachability analysis.
  AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(FD);
  const CFG *Cfg = ADC ? ADC->getCFG() : nullptr;
  CFGStmtIndex CfgIndex;
  buildCFGStmtIndex(Cfg, CfgIndex);

  detectAndReport(FD, Labels, Gotos, Frees, Assigns, Cfg, CfgIndex, BR, Ctx);
}

void SAGenTestChecker::detectAndReport(const FunctionDecl *FD,
                                       const std::vector<LabelInfo> &Labels,
                                       const std::vector<GotoInfo> &Gotos,
                                       const std::vector<FreeSite> &Frees,
                                       const std::vector<AssignInfo> &Assigns,
                                       const CFG *Cfg, const CFGStmtIndex &CfgIndex,
                                       BugReporter &BR, ASTContext &AC) const {
  const SourceManager &SM = AC.getSourceManager();

  auto getLabelLoc = [&](const LabelDecl *LD) -> SourceLocation {
    for (const auto &LI : Labels) {
      if (LI.LDecl == LD)
        return LI.Loc;
    }
    return SourceLocation();
  };

  for (const auto &FS : Frees) {
    if (!FS.P || !FS.CleanupLabel || !FS.FreeCall)
      continue;

    SourceLocation FreeLoc = FS.FreeLoc;
    SourceLocation CleanupLoc = getLabelLoc(FS.CleanupLabel);
    if (FreeLoc.isInvalid() || CleanupLoc.isInvalid())
      continue;

    // Find a backward goto (retry) after the free that does NOT target the cleanup label.
    for (const auto &GR : Gotos) {
      if (!GR.Target)
        continue;

      if (isSelfCleanupJump(GR, FS))
        continue;

      SourceLocation GoLoc = GR.Loc;
      SourceLocation TargetLoc = getLabelLoc(GR.Target);
      if (GoLoc.isInvalid() || TargetLoc.isInvalid())
        continue;

      // Must be: free ... goto restart_label; where restart_label is before free.
      if (!(before(SM, FreeLoc, GoLoc) && before(SM, TargetLoc, FreeLoc)))
        continue;

      // New: Require that the backward goto is actually reachable from the cleanup free.
      if (!cfgReachable(Cfg, CfgIndex, FS.FreeCall, GR.G))
        continue;

      // Safety check 1: reset to NULL between free and retry goto
      bool ResetBetween = false;
      for (const auto &AI : Assigns) {
        if (AI.P != FS.P)
          continue;
        if (AI.ResetToNull && strictlyBetween(SM, AI.Loc, FreeLoc, GoLoc)) {
          ResetBetween = true;
          break;
        }
      }
      if (ResetBetween)
        continue; // safe for this retry goto

      // The earliest assignment to P after the restart label (if any).
      const AssignInfo *Earliest = nullptr;
      for (const auto &AI : Assigns) {
        if (AI.P != FS.P)
          continue;
        if (before(SM, TargetLoc, AI.Loc)) {
          if (!Earliest || before(SM, AI.Loc, Earliest->Loc))
            Earliest = &AI;
        }
      }

      // Safety check 2: Look for an early goto to the cleanup label between restart label and earliest assignment.
      bool EarlyGotoToCleanup = false;
      const Stmt *RestartEntryStmt = getFirstStmtAfterLabel(Labels, GR.Target);

      for (const auto &GE : Gotos) {
        if (GE.Target != FS.CleanupLabel)
          continue;

        SourceLocation ELoc = GE.Loc;
        if (!before(SM, TargetLoc, ELoc))
          continue;

        if (Earliest && !before(SM, ELoc, Earliest->Loc))
          continue;

        // Require reachability from the restart label entry to this early goto.
        if (RestartEntryStmt && cfgReachable(Cfg, CfgIndex, RestartEntryStmt, GE.G)) {
          EarlyGotoToCleanup = true;
          break;
        }
      }

      // Important fix: Do not flag unless we actually found an early goto to cleanup
      // after restart. Previously this was flagged unconditionally if Earliest == nullptr.
      if (EarlyGotoToCleanup) {
        auto R = std::make_unique<BasicBugReport>(
            *BT,
            "Pointer freed in cleanup then retried without resetting to NULL; "
            "early goto can double free",
            PathDiagnosticLocation(FS.FreeLoc, SM));
        R->addRange(FS.FreeCall->getSourceRange());
        BR.emitReport(std::move(R));
        break;
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects possible double free across replay/retry loop due to missing NULL reset",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
