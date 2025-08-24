Refinement Plan:
- Root cause: The checker treats any backward goto after a cleanup free as a potential retry loop without verifying that it is actually a replay/retry jump and that there is an early goto-to-cleanup before the (re)allocation of the freed pointer. In the false positive function (ovl_get_fh), gotos target the cleanup label itself and there is no retry/replay loop. The checker also misses validating that the restart goto is under a conditional (as in the intended bug) and that there is a true allocation segment between the restart label and the cleanup free.
- Fixes:
  1. Skip self-cleanup jumps (already present) and additionally require the restart goto to be inside a conditional (IfStmt) to match real replay/retry patterns like the smb2_set_ea bug.
  2. Track allocation sites (kmalloc/kzalloc/…) of the pointer and require that there is an allocation between the restart label and the cleanup free.
  3. Require evidence of an early goto to the cleanup label between the restart label and the earliest allocation of the pointer (this models the “second iteration early exit before reallocation” risk).
  4. Keep the existing “p reset to NULL between free and restart?” safety rule; if reset, do not warn.
- Edge cases and regressions:
  - Self-cleanup gotos and functions without any backward retry goto will no longer be flagged.
  - The checker still reports the intended smb2_set_ea bug, because it has a conditional restart goto, an allocation of ea between replay_again and the cleanup, and early gotos to the cleanup before allocation on the retry path.
  - To minimize regressions, allocation detection recognizes common kernel allocation names (kzalloc/kmalloc/etc.). This is sufficient to hit the target bug and avoid the reported FP.
- Compatibility: The solution is AST-only and compatible with Clang-18. No includes are removed. We added local helpers only.

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
#include <memory>
#include <queue>
#include <unordered_set>

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

struct AllocSite {
  const VarDecl *P = nullptr;
  const CallExpr *Call = nullptr;             // allocator call
  SourceLocation Loc;
};

static bool isAllocatorName(StringRef N) {
  // A conservative set sufficient for the target bug and common kernel code.
  return N == "kzalloc" || N == "kmalloc" || N == "kmalloc_array" ||
         N == "kcalloc" || N == "kvzalloc" || N == "kvalloc" ||
         N == "kvmalloc";
}

static bool isFreeName(StringRef N) {
  return N == "kfree" || N == "kvfree";
}

class BodyScanner : public RecursiveASTVisitor<BodyScanner> {
public:
  BodyScanner(ASTContext &Ctx,
              std::vector<LabelInfo> &Labels,
              std::vector<GotoInfo> &Gotos,
              std::vector<FreeSite> &Frees,
              std::vector<AssignInfo> &Assigns,
              std::vector<AllocSite> &Allocs)
      : Ctx(Ctx), SM(Ctx.getSourceManager()), Labels(Labels), Gotos(Gotos),
        Frees(Frees), Assigns(Assigns), Allocs(Allocs) {}

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

    // Track NULL resets.
    bool IsNull = isNullPointerExpr(RHS);
    AssignInfo AI;
    AI.P = VD;
    AI.Loc = getExpansionLocSafe(BO->getExprLoc());
    AI.ResetToNull = IsNull;
    Assigns.push_back(AI);

    // Track allocator assignments: p = kmalloc(...);
    const CallExpr *Call = dyn_cast<CallExpr>(RHS->IgnoreParenImpCasts());
    if (Call) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        if (const IdentifierInfo *II = FD->getIdentifier()) {
          if (isAllocatorName(II->getName())) {
            AllocSite AS;
            AS.P = VD;
            AS.Call = Call;
            AS.Loc = getExpansionLocSafe(Call->getExprLoc());
            Allocs.push_back(AS);
          }
        }
      }
    }
    return true;
  }

  bool VisitDeclStmt(DeclStmt *DS) {
    for (auto *D : DS->decls()) {
      auto *VD = dyn_cast<VarDecl>(D);
      if (!VD)
        continue;
      if (!VD->getType()->isAnyPointerType())
        continue;

      // Track initialization to NULL.
      if (VD->hasInit()) {
        const Expr *Init = VD->getInit();
        bool IsNull = isNullPointerExpr(Init);
        AssignInfo AI;
        AI.P = VD;
        AI.Loc = getExpansionLocSafe(VD->getLocation());
        AI.ResetToNull = IsNull;
        Assigns.push_back(AI);

        // Track allocator initialization: T *p = kmalloc(...);
        const CallExpr *Call = dyn_cast<CallExpr>(Init->IgnoreParenImpCasts());
        if (Call) {
          if (const FunctionDecl *FD = Call->getDirectCallee()) {
            if (const IdentifierInfo *II = FD->getIdentifier()) {
              if (isAllocatorName(II->getName())) {
                AllocSite AS;
                AS.P = VD;
                AS.Call = Call;
                AS.Loc = getExpansionLocSafe(Call->getExprLoc());
                Allocs.push_back(AS);
              }
            }
          }
        }
      }
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
  std::vector<AllocSite> &Allocs;

  SourceLocation getExpansionLocSafe(SourceLocation L) const {
    if (L.isInvalid())
      return L;
    return SM.getExpansionLoc(L);
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
        return GR.Target && FS.CleanupLabel && (GR.Target == FS.CleanupLabel);
      }

      static const IfStmt *findIfAncestor(const Stmt *S, ASTContext &AC);

      void detectAndReport(const FunctionDecl *FD,
                           const std::vector<LabelInfo> &Labels,
                           const std::vector<GotoInfo> &Gotos,
                           const std::vector<FreeSite> &Frees,
                           const std::vector<AssignInfo> &Assigns,
                           const std::vector<AllocSite> &Allocs,
                           BugReporter &BR, ASTContext &AC) const;
};

const IfStmt *SAGenTestChecker::findIfAncestor(const Stmt *S, ASTContext &AC) {
  if (!S)
    return nullptr;

  // BFS up the parent chain to find an IfStmt.
  std::queue<llvm::DynTypedNode> Q;
  std::unordered_set<const void *> Visited;

  Q.push(llvm::DynTypedNode::create(*S));
  Visited.insert(S);

  unsigned Steps = 0, MaxSteps = 1024;
  while (!Q.empty() && Steps++ < MaxSteps) {
    llvm::DynTypedNode Cur = Q.front();
    Q.pop();

    auto Parents = AC.getParents(Cur);
    for (const auto &P : Parents) {
      if (const IfStmt *IS = P.get<IfStmt>())
        return IS;

      if (const Stmt *PS = P.get<Stmt>()) {
        if (!Visited.count(PS)) {
          Visited.insert(PS);
          Q.push(llvm::DynTypedNode::create(*PS));
        }
      } else if (const Decl *PD = P.get<Decl>()) {
        if (!Visited.count(PD)) {
          Visited.insert(PD);
          Q.push(llvm::DynTypedNode::create(*PD));
        }
      }
    }
  }
  return nullptr;
}

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
  std::vector<AllocSite> Allocs;

  BodyScanner Scanner(Ctx, Labels, Gotos, Frees, Assigns, Allocs);
  Scanner.TraverseStmt(const_cast<Stmt *>(Body));

  detectAndReport(FD, Labels, Gotos, Frees, Assigns, Allocs, BR, Ctx);
}

void SAGenTestChecker::detectAndReport(const FunctionDecl *FD,
                                       const std::vector<LabelInfo> &Labels,
                                       const std::vector<GotoInfo> &Gotos,
                                       const std::vector<FreeSite> &Frees,
                                       const std::vector<AssignInfo> &Assigns,
                                       const std::vector<AllocSite> &Allocs,
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

    // Consider only backward gotos (potential retries) occurring after the free
    // and targeting a label before the free, not the cleanup label itself.
    for (const auto &GR : Gotos) {
      if (!GR.Target)
        continue;

      if (isSelfCleanupJump(GR, FS))
        continue;

      SourceLocation GoLoc = GR.Loc;
      SourceLocation TargetLoc = getLabelLoc(GR.Target);
      if (GoLoc.isInvalid() || TargetLoc.isInvalid())
        continue;

      // Must be: free ... goto restart_label; with restart_label before free.
      if (!(before(SM, FreeLoc, GoLoc) && before(SM, TargetLoc, FreeLoc)))
        continue;

      // Heuristic: In real replay/retry bugs the restart goto is conditional.
      // Require an enclosing IfStmt for the goto to reduce false positives
      // where the jump is just another cleanup flow.
      if (!findIfAncestor(GR.G, AC))
        continue;

      // Safety check 1: reset to NULL between free and the retry goto?
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
        continue;

      // Find the earliest allocation of P after restart label and before the free.
      const AllocSite *EarliestAlloc = nullptr;
      for (const auto &AS : Allocs) {
        if (AS.P != FS.P)
          continue;
        if (!before(SM, TargetLoc, AS.Loc))
          continue;
        if (!before(SM, AS.Loc, FreeLoc))
          continue;
        if (!EarliestAlloc || before(SM, AS.Loc, EarliestAlloc->Loc))
          EarliestAlloc = &AS;
      }
      if (!EarliestAlloc)
        continue; // No allocation in the segment - not our pattern.

      // Look for an early goto to cleanup between restart label and the earliest allocation.
      bool EarlyGotoToCleanupBeforeAlloc = false;
      for (const auto &GE : Gotos) {
        if (GE.Target != FS.CleanupLabel)
          continue;
        SourceLocation ELoc = GE.Loc;
        if (strictlyBetween(SM, ELoc, TargetLoc, EarliestAlloc->Loc)) {
          EarlyGotoToCleanupBeforeAlloc = true;
          break;
        }
      }
      if (!EarlyGotoToCleanupBeforeAlloc)
        continue;

      // All conditions satisfied: report.
      auto R = std::make_unique<BasicBugReport>(
          *BT,
          "Pointer freed in cleanup then retried without resetting to NULL; "
          "early goto can double free",
          PathDiagnosticLocation(FS.FreeLoc, SM));
      R->addRange(FS.FreeCall->getSourceRange());
      BR.emitReport(std::move(R));
      break; // Avoid duplicates for this FreeSite.
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
