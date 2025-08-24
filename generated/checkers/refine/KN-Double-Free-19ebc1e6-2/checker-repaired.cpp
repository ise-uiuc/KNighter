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

// No custom program states are necessary for this structural checker.

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
    // Use Clang's helper to decide null pointer constants
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

    // Local simple walker to look for CallExprs
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

      void detectAndReport(const FunctionDecl *FD,
                           const std::vector<LabelInfo> &Labels,
                           const std::vector<GotoInfo> &Gotos,
                           const std::vector<FreeSite> &Frees,
                           const std::vector<AssignInfo> &Assigns,
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

  detectAndReport(FD, Labels, Gotos, Frees, Assigns, BR, Ctx);
}

void SAGenTestChecker::detectAndReport(const FunctionDecl *FD,
                                       const std::vector<LabelInfo> &Labels,
                                       const std::vector<GotoInfo> &Gotos,
                                       const std::vector<FreeSite> &Frees,
                                       const std::vector<AssignInfo> &Assigns,
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

    // Find a backward goto (retry) after the free.
    for (const auto &GR : Gotos) {
      if (!GR.Target)
        continue;

      SourceLocation GoLoc = GR.Loc;
      SourceLocation TargetLoc = getLabelLoc(GR.Target);
      if (GoLoc.isInvalid() || TargetLoc.isInvalid())
        continue;

      // Must be: free ... goto restart_label; where restart_label is before free.
      if (!(before(SM, FreeLoc, GoLoc) && before(SM, TargetLoc, FreeLoc)))
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

      // Safety check 2: earliest assignment after restart label
      const AssignInfo *Earliest = nullptr;
      for (const auto &AI : Assigns) {
        if (AI.P != FS.P)
          continue;
        if (before(SM, TargetLoc, AI.Loc)) {
          if (!Earliest || before(SM, AI.Loc, Earliest->Loc))
            Earliest = &AI;
        }
      }

      // Look for an early goto to the cleanup label between restart label and earliest assignment.
      bool EarlyGotoToCleanup = false;
      for (const auto &GE : Gotos) {
        if (GE.Target != FS.CleanupLabel)
          continue;
        SourceLocation ELoc = GE.Loc;
        if (!before(SM, TargetLoc, ELoc))
          continue;
        if (Earliest) {
          if (before(SM, ELoc, Earliest->Loc)) {
            EarlyGotoToCleanup = true;
            break;
          }
        } else {
          // No assignment after restart; any early goto to cleanup after restart is problematic.
          EarlyGotoToCleanup = true;
          break;
        }
      }

      if (EarlyGotoToCleanup) {
        // Report at the free call location using a SourceLocation-based PathDiagnosticLocation.
        auto R = std::make_unique<BasicBugReport>(
            *BT,
            "Pointer freed in cleanup then retried without resetting to NULL; "
            "early goto can double free",
            PathDiagnosticLocation(FS.FreeLoc, SM));
        R->addRange(FS.FreeCall->getSourceRange());
        BR.emitReport(std::move(R));
        // No need to continue for more gotos for this FreeSite; one is enough.
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
