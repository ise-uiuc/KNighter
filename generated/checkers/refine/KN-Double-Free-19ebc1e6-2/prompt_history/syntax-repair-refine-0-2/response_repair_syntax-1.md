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

struct AllocInfo {
  const VarDecl *P = nullptr;
  const CallExpr *Call = nullptr; // allocation call assigned to P
  SourceLocation Loc;
};

class BodyScanner : public RecursiveASTVisitor<BodyScanner> {
public:
  BodyScanner(ASTContext &Ctx,
              std::vector<LabelInfo> &Labels,
              std::vector<GotoInfo> &Gotos,
              std::vector<FreeSite> &Frees,
              std::vector<AssignInfo> &Assigns,
              std::vector<AllocInfo> &Allocs)
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

    // Track NULL resets
    bool IsNull = isNullPointerExpr(RHS);
    AssignInfo AI;
    AI.P = VD;
    AI.Loc = getExpansionLocSafe(BO->getExprLoc());
    AI.ResetToNull = IsNull;
    Assigns.push_back(AI);

    // Track allocations assigned to the pointer
    const CallExpr *AllocCall = nullptr;
    if (isAllocatingExpr(RHS, AllocCall) && AllocCall) {
      AllocInfo AL;
      AL.P = VD;
      AL.Call = AllocCall;
      AL.Loc = getExpansionLocSafe(AllocCall->getExprLoc());
      Allocs.push_back(AL);
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

      if (VD->hasInit()) {
        const Expr *Init = VD->getInit();

        // Track NULL-initializations
        bool IsNull = isNullPointerExpr(Init);
        AssignInfo AI;
        AI.P = VD;
        AI.Loc = getExpansionLocSafe(VD->getLocation());
        AI.ResetToNull = IsNull;
        Assigns.push_back(AI);

        // Track allocations in initializers
        const CallExpr *AllocCall = nullptr;
        if (isAllocatingExpr(Init, AllocCall) && AllocCall) {
          AllocInfo AL;
          AL.P = VD;
          AL.Call = AllocCall;
          AL.Loc = getExpansionLocSafe(AllocCall->getExprLoc());
          Allocs.push_back(AL);
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
  std::vector<AllocInfo> &Allocs;

  SourceLocation getExpansionLocSafe(SourceLocation L) const {
    if (L.isInvalid())
      return L;
    return SM.getExpansionLoc(L);
  }

  static bool isFreeName(StringRef N) {
    return N == "kfree" || N == "kvfree";
  }

  static bool isAllocName(StringRef N) {
    // Common Linux allocator names that are freed by kfree/kvfree.
    // This list is intentionally broad to reduce FNs without
    // exploding complexity.
    return N == "kmalloc" ||
           N == "kzalloc" ||
           N == "kcalloc" ||
           N == "kvzalloc" ||
           N == "kvmalloc" ||
           N == "kvmalloc_array" ||
           N == "kmemdup" ||
           N == "krealloc" ||
           N == "kstrdup" ||
           N == "kstrndup" ||
           N == "kmalloc_array" ||
           N == "kmemdup_nul";
  }

  static bool isPointerReturningCall(const CallExpr *CE) {
    if (!CE)
      return false;
    QualType RT = CE->getType();
    return !RT.isNull() && RT->isAnyPointerType();
  }

  bool isNullPointerExpr(const Expr *E) const {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull) !=
           Expr::NPCK_NotNull;
  }

  bool isAllocatingExpr(const Expr *E, const CallExpr *&OutCall) const {
    OutCall = nullptr;
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    const auto *CE = dyn_cast<CallExpr>(E);
    if (!CE)
      return false;

    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD) {
      if (const IdentifierInfo *II = FD->getIdentifier()) {
        if (isAllocName(II->getName())) {
          OutCall = CE;
          return true;
        }
      }
    }

    // Heuristic: any direct call returning a pointer might be an allocation-like
    // source. Keep this as a fallback to avoid FNs where allocation helpers are
    // not directly named kmalloc/kzalloc, etc.
    if (isPointerReturningCall(CE)) {
      OutCall = CE;
      return true;
    }

    return false;
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
        // A restart candidate must not be a goto back to the same cleanup label.
        return GR.Target && FS.CleanupLabel && (GR.Target == FS.CleanupLabel);
      }

      void detectAndReport(const FunctionDecl *FD,
                           const std::vector<LabelInfo> &Labels,
                           const std::vector<GotoInfo> &Gotos,
                           const std::vector<FreeSite> &Frees,
                           const std::vector<AssignInfo> &Assigns,
                           const std::vector<AllocInfo> &Allocs,
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
  std::vector<AllocInfo> Allocs;

  BodyScanner Scanner(Ctx, Labels, Gotos, Frees, Assigns, Allocs);
  Scanner.TraverseStmt(const_cast<Stmt *>(Body));

  detectAndReport(FD, Labels, Gotos, Frees, Assigns, Allocs, BR, Ctx);
}

void SAGenTestChecker::detectAndReport(const FunctionDecl *FD,
                                       const std::vector<LabelInfo> &Labels,
                                       const std::vector<GotoInfo> &Gotos,
                                       const std::vector<FreeSite> &Frees,
                                       const std::vector<AssignInfo> &Assigns,
                                       const std::vector<AllocInfo> &Allocs,
                                       BugReporter &BR, ASTContext &AC) const {
  const SourceManager &SM = AC.getSourceManager();

  auto getLabelLoc = [&](const LabelDecl *LD) -> SourceLocation {
    for (const auto &LI : Labels) {
      if (LI.LDecl == LD)
        return LI.Loc;
    }
    return SourceLocation();
  };

  auto findFirstAllocBetween = [&](const VarDecl *P, SourceLocation L, SourceLocation R)
      -> const AllocInfo* {
    const AllocInfo *Best = nullptr;
    for (const auto &AL : Allocs) {
      if (AL.P != P)
        continue;
      if (!strictlyBetween(SM, AL.Loc, L, R))
        continue;
      if (!Best || before(SM, AL.Loc, Best->Loc))
        Best = &AL;
    }
    return Best;
  };

  auto findFirstNullResetAfter = [&](const VarDecl *P, SourceLocation L)
      -> const AssignInfo* {
    const AssignInfo *Best = nullptr;
    for (const auto &AI : Assigns) {
      if (AI.P != P || !AI.ResetToNull)
        continue;
      if (!before(SM, L, AI.Loc))
        continue;
      if (!Best || before(SM, AI.Loc, Best->Loc))
        Best = &AI;
    }
    return Best;
  };

  for (const auto &FS : Frees) {
    if (!FS.P || !FS.CleanupLabel || !FS.FreeCall)
      continue;

    SourceLocation FreeLoc = FS.FreeLoc;
    SourceLocation CleanupLoc = getLabelLoc(FS.CleanupLabel);
    if (FreeLoc.isInvalid() || CleanupLoc.isInvalid())
      continue;

    // Find a backward goto (potential retry) after the free that does NOT target the cleanup label.
    for (const auto &GR : Gotos) {
      if (!GR.Target)
        continue;

      if (isSelfCleanupJump(GR, FS))
        continue;

      SourceLocation GoLoc = GR.Loc;
      SourceLocation TargetLoc = getLabelLoc(GR.Target);
      if (GoLoc.isInvalid() || TargetLoc.isInvalid())
        continue;

      // Candidate retry if: free ... goto restart_label; and restart_label is before free.
      if (!(before(SM, FreeLoc, GoLoc) && before(SM, TargetLoc, FreeLoc)))
        continue;

      // New FP filter 1: Require at least one allocation of P between restart label and cleanup free.
      const AllocInfo *FirstAlloc = findFirstAllocBetween(FS.P, TargetLoc, FreeLoc);
      if (!FirstAlloc)
        continue; // No allocation between restart and cleanup -> unlikely to be the targeted pattern

      // New FP filter 2: Define mitigation point: earliest of (NULL reset after restart) or (first allocation).
      const AssignInfo *FirstNullReset = findFirstNullResetAfter(FS.P, TargetLoc);

      SourceLocation MitigationLoc;
      bool HaveMitigation = false;
      if (FirstNullReset && before(SM, FirstNullReset->Loc, FirstAlloc->Loc)) {
        MitigationLoc = FirstNullReset->Loc;
        HaveMitigation = true;
      } else {
        MitigationLoc = FirstAlloc->Loc;
        HaveMitigation = true;
      }

      if (!HaveMitigation)
        continue;

      // Existing safety: if NULL reset occurs between free and the retry goto, it's safe for this retry.
      bool ResetBetweenFreeAndRetry = false;
      for (const auto &AI : Assigns) {
        if (AI.P != FS.P)
          continue;
        if (AI.ResetToNull && strictlyBetween(SM, AI.Loc, FreeLoc, GoLoc)) {
          ResetBetweenFreeAndRetry = true;
          break;
        }
      }
      if (ResetBetweenFreeAndRetry)
        continue;

      // Now, look for an early goto to the cleanup label between restart label and the mitigation point.
      bool EarlyGotoToCleanup = false;
      for (const auto &GE : Gotos) {
        if (GE.Target != FS.CleanupLabel)
          continue;

        SourceLocation ELoc = GE.Loc;
        if (strictlyBetween(SM, ELoc, TargetLoc, MitigationLoc)) {
          EarlyGotoToCleanup = true;
          break;
        }
      }

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
