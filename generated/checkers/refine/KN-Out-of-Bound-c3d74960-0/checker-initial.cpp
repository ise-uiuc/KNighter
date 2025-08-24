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
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/DeclStmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is needed. This checker is a mostly-syntactic matcher.

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Per-CRTC array indexed by max_links", "Memory Error")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // (no ProgramState helpers needed)
};

// ---- Helper functions and visitor implementation ----

static bool ExprHasNameAST(const Expr *E, StringRef Name, ASTContext &AC) {
  if (!E)
    return false;
  const SourceManager &SM = AC.getSourceManager();
  const LangOptions &LangOpts = AC.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  return Text.contains(Name);
}

static StringRef getCalleeName(const CallExpr *CE) {
  if (!CE)
    return StringRef();
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (const IdentifierInfo *II = FD->getIdentifier())
      return II->getName();
  }
  return StringRef();
}

static bool isAllocCallOfInterest(const Expr *InitE, const CallExpr *&OutCE, const Expr *&OutCountArg, ASTContext &AC) {
  OutCE = nullptr;
  OutCountArg = nullptr;
  if (!InitE)
    return false;

  const Expr *E = InitE->IgnoreParenImpCasts();
  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;

  StringRef Name = getCalleeName(CE);
  if (Name.empty()) {
    // Fallback: try textual match if we couldn't get a direct callee (rare)
    if (!ExprHasNameAST(CE, "kcalloc", AC) && !ExprHasNameAST(CE, "kmalloc_array", AC))
      return false;
  } else {
    if (!(Name == "kcalloc" || Name == "kmalloc_array"))
      return false;
  }

  if (CE->getNumArgs() < 1)
    return false;

  OutCE = CE;
  OutCountArg = CE->getArg(0);
  return true;
}

class MaxLinksLoopVisitor : public RecursiveASTVisitor<MaxLinksLoopVisitor> {
public:
  MaxLinksLoopVisitor(ASTContext &AC, BugReporter &BR, BugType &BT,
                      AnalysisDeclContext *ADC)
      : AC(AC), BR(BR), BT(BT), ADC(ADC) {}

  bool VisitDeclStmt(const DeclStmt *DS) {
    // Look for: Type *p = kcalloc(num_crtc or AMDGPU_MAX_CRTCS, ...);
    for (const Decl *D : DS->decls()) {
      const VarDecl *VD = dyn_cast<VarDecl>(D);
      if (!VD)
        continue;
      const Expr *Init = VD->getInit();
      const CallExpr *CE = nullptr;
      const Expr *CountArg = nullptr;
      if (isAllocCallOfInterest(Init, CE, CountArg, AC)) {
        if (CountArg &&
            (ExprHasNameAST(CountArg, "num_crtc", AC) ||
             ExprHasNameAST(CountArg, "AMDGPU_MAX_CRTCS", AC))) {
          PerCrtcSizedLocals[VD] = true;
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(const BinaryOperator *BO) {
    if (!BO || !BO->isAssignmentOp())
      return true;

    const Expr *RHS = BO->getRHS();
    const CallExpr *CE = nullptr;
    const Expr *CountArg = nullptr;
    if (!isAllocCallOfInterest(RHS, CE, CountArg, AC))
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return true;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return true;

    if (CountArg &&
        (ExprHasNameAST(CountArg, "num_crtc", AC) ||
         ExprHasNameAST(CountArg, "AMDGPU_MAX_CRTCS", AC))) {
      PerCrtcSizedLocals[VD] = true;
    }

    return true;
  }

  bool VisitForStmt(const ForStmt *FS) {
    if (!FS)
      return true;
    processLoop(FS->getCond(), FS->getBody());
    return true;
  }

  bool VisitWhileStmt(const WhileStmt *WS) {
    if (!WS)
      return true;
    processLoop(WS->getCond(), WS->getBody());
    return true;
  }

private:
  ASTContext &AC;
  BugReporter &BR;
  BugType &BT;
  AnalysisDeclContext *ADC;

  llvm::DenseMap<const VarDecl *, bool> PerCrtcSizedLocals;
  llvm::SmallPtrSet<const Stmt *, 16> Reported;

  void collectVarsInExpr(const Expr *E, llvm::SmallVectorImpl<const VarDecl *> &Out) {
    if (!E)
      return;
    class VarCollector : public RecursiveASTVisitor<VarCollector> {
    public:
      VarCollector(llvm::SmallVectorImpl<const VarDecl *> &Out) : Out(Out) {}
      bool VisitDeclRefExpr(const DeclRefExpr *DRE) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (VD->getType().getTypePtrOrNull() &&
              VD->getType()->isIntegerType())
            Out.push_back(VD);
        }
        return true;
      }
    private:
      llvm::SmallVectorImpl<const VarDecl *> &Out;
    } VC(Out);
    VC.TraverseStmt(const_cast<Expr *>(E));
  }

  bool baseIsPerCrtc(const Expr *Base) {
    if (!Base)
      return false;
    Base = Base->IgnoreParenImpCasts();

    // If base is a known local allocated by num_crtc/AMDGPU_MAX_CRTCS
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        auto It = PerCrtcSizedLocals.find(VD);
        if (It != PerCrtcSizedLocals.end() && It->second)
          return true;
      }
    }

    // Heuristic name matches for known per-CRTC arrays
    if (ExprHasNameAST(Base, "secure_display_ctxs", AC))
      return true;

    if (ExprHasNameAST(Base, "crtcs", AC) && ExprHasNameAST(Base, "mode_info", AC))
      return true;

    return false;
  }

  void processLoop(const Expr *Cond, const Stmt *Body) {
    if (!Cond || !Body)
      return;

    // We only care about loops whose condition involves max_links.
    if (!ExprHasNameAST(Cond, "max_links", AC))
      return;

    llvm::SmallVector<const VarDecl *, 8> CandidateIdxVars;
    collectVarsInExpr(Cond, CandidateIdxVars);
    if (CandidateIdxVars.empty())
      return;

    // Scan loop body for array subscripts using those variables as indices.
    class BodyScanner : public RecursiveASTVisitor<BodyScanner> {
    public:
      BodyScanner(MaxLinksLoopVisitor &Parent,
                  ArrayRef<const VarDecl *> IdxVars,
                  const Expr *Cond)
          : P(Parent), Cond(Cond) {
        for (const VarDecl *VD : IdxVars)
          IdxSet.insert(VD);
      }

      bool VisitArraySubscriptExpr(const ArraySubscriptExpr *ASE) {
        if (!ASE)
          return true;
        const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
        const DeclRefExpr *IdxDRE = dyn_cast<DeclRefExpr>(Idx);
        if (!IdxDRE)
          return true;
        const VarDecl *VD = dyn_cast<VarDecl>(IdxDRE->getDecl());
        if (!VD || !IdxSet.count(VD))
          return true;

        const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
        if (!Base)
          return true;

        if (P.baseIsPerCrtc(Base)) {
          // Report once per subscript site.
          if (!P.Reported.count(ASE)) {
            P.Reported.insert(ASE);

            PathDiagnosticLocation Loc =
                PathDiagnosticLocation::createBegin(ASE, P.BR.getSourceManager(), P.ADC);
            auto R = std::make_unique<BasicBugReport>(
                P.BT,
                "Possible out-of-bounds: loop bound uses dc->caps.max_links but "
                "indexes a per-CRTC array; use adev->mode_info.num_crtc.",
                Loc);
            R->addRange(ASE->getSourceRange());
            if (Cond)
              R->addRange(Cond->getSourceRange());
            P.BR.emitReport(std::move(R));
          }
        }

        return true;
      }

    private:
      MaxLinksLoopVisitor &P;
      const Expr *Cond;
      llvm::SmallPtrSet<const VarDecl *, 8> IdxSet;
    } Scanner(*this, CandidateIdxVars, Cond);

    Scanner.TraverseStmt(const_cast<Stmt *>(Body));
  }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->doesThisDeclarationHaveABody())
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  MaxLinksLoopVisitor V(Mgr.getASTContext(), BR, *BT, Mgr.getAnalysisDeclContext(D));
  V.TraverseStmt(Body);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects loops bounded by dc->caps.max_links that index per-CRTC arrays (possible OOB); use num_crtc",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
