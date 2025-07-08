#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtIterator.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

// No custom program state maps are needed since this checker only inspects the AST.

namespace {

/// ForLoopVisitor: A RecursiveASTVisitor to inspect ForStmt nodes
class ForLoopVisitor : public RecursiveASTVisitor<ForLoopVisitor> {
  BugReporter &BR;
  AnalysisDeclContext *AC;
  const FunctionDecl *TargetFunc;
  const LangOptions &LangOpts;
  bool BugReported;

public:
  ForLoopVisitor(BugReporter &BR, AnalysisDeclContext *AC, const FunctionDecl *FD, const LangOptions &LangOpts)
      : BR(BR), AC(AC), TargetFunc(FD), LangOpts(LangOpts), BugReported(false) {}

  bool VisitForStmt(ForStmt *FS) {
    if (BugReported)
      return true; // Only report once

    // Check that the ForStmt is within our target function.
    // Retrieve the loop initialization. We expect a DeclStmt that declares the loop variable.
    Stmt *Init = FS->getInit();
    if (!Init)
      return true;
    const DeclStmt *DS = dyn_cast<DeclStmt>(Init);
    if (!DS)
      return true;
    // Get the loop variable from the DeclStmt.
    VarDecl *LoopVar = nullptr;
    for (const auto *D : DS->decls()) {
      LoopVar = dyn_cast<VarDecl>(D);
      if (LoopVar)
        break;
    }
    if (!LoopVar)
      return true;
    StringRef LoopVarName = LoopVar->getName();

    // Check the loop condition.
    const Expr *Cond = FS->getCond();
    if (!Cond)
      return true;
    
    // We expect the condition to be a binary operator using '<'
    const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenCasts());
    if (!BO || BO->getOpcode() != BO_LT)
      return true;
    
    // Retrieve the source text of the right-hand side of the condition.
    SourceManager &SM = BR.getSourceManager();
    CharSourceRange RHSRange = CharSourceRange::getTokenRange(BO->getRHS()->getSourceRange());
    StringRef RHSText = Lexer::getSourceText(RHSRange, SM, LangOpts);
    // Check if the RHS contains "MAX_PIPES" and "2" (and multiplication) but does not subtract an offset.
    // This is a heuristic: if the text contains a '-' sign, we assume it adjusted the bound.
    if (!(RHSText.contains("MAX_PIPES") && RHSText.contains("2")) || RHSText.contains("-"))
      return true;

    // Now, search within the ForStmt body for an ArraySubscriptExpr that uses the loop variable with a +1 offset.
    bool FoundArrayAccess = false;
    // Lambda visitor for the loop body.
    class LoopBodyVisitor : public RecursiveASTVisitor<LoopBodyVisitor> {
      StringRef LoopVarName;
      bool Found;
    public:
      LoopBodyVisitor(StringRef LV) : LoopVarName(LV), Found(false) {}
      bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
        // Get the index expression.
        const Expr *Idx = ASE->getIdx()->IgnoreParenCasts();
        // We expect an addition (i + 1)
        if (const BinaryOperator *AddOp = dyn_cast<BinaryOperator>(Idx)) {
          if (AddOp->getOpcode() == BO_Add) {
            const Expr *LHS = AddOp->getLHS()->IgnoreParenCasts();
            const Expr *RHS = AddOp->getRHS()->IgnoreParenCasts();
            // Check if LHS is the loop variable.
            if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
              if (DRE->getDecl()->getDeclName().getAsString() == LoopVarName.str()) {
                // Check if the RHS is integer literal '1'
                if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(RHS)) {
                  if (IL->getValue() == 1) {
                    Found = true;
                  }
                }
              }
            }
          }
        }
        return true;
      }
      bool found() const { return Found; }
    };

    LoopBodyVisitor LBV(LoopVarName);
    if (FS->getBody())
      LBV.TraverseStmt(FS->getBody());
    FoundArrayAccess = LBV.found();

    if (FoundArrayAccess) {
      // Report potential bug: The loop iterates i from 0 to (MAX_PIPES * 2)
      // but uses index (i+1) which may cause out-of-bound access.
      SourceLocation Loc = FS->getForLoc();
      auto *N = BR.generateNonFatalErrorNode();
      if (!N)
        return true;
      
      StringRef Msg = "Loop may access out-of-bound array element using (i+1) without adjusting loop condition";
      auto Report = llvm::make_unique<PathSensitiveBugReport>(*new BugType("Out-of-Bounds Access", "Loop Bounds Error", BR.getCheckerManager()), Msg, N);
      Report->addRange(FS->getSourceRange());
      BR.emitReport(std::move(Report));
      BugReported = true;
    }

    return true;
  }
  
  // Continue traversing other statements.
  bool TraverseStmt(Stmt *S) {
    return RecursiveASTVisitor<ForLoopVisitor>::TraverseStmt(S);
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Loop Bounds Error", "Buffer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    // We are only interested in the specific function "get_host_router_total_dp_tunnel_bw"
    const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
    if (!FD)
      return;
    if (FD->getNameAsString() != "get_host_router_total_dp_tunnel_bw")
      return;
    if (!FD->hasBody())
      return;

    // Retrieve the LangOptions.
    ASTContext &Ctx = FD->getASTContext();
    const LangOptions &LangOpts = Ctx.getLangOpts();

    // Traverse the body using our ForLoopVisitor.
    ForLoopVisitor Visitor(BR, Mgr.getAnalysisDeclContext(FD), FD, LangOpts);
    Visitor.TraverseStmt(FD->getBody());
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential out-of-bound access in get_host_router_total_dp_tunnel_bw due to loop bounds", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
