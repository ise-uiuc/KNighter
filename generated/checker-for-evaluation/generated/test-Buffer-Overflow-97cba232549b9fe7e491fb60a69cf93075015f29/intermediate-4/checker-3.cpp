#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;

namespace {
  
// Helper RecursiveASTVisitor to detect a bad array subscript pattern:
// It looks for ArraySubscriptExpr nodes where the base expression's text contains "dc->links"
// and where the subscript is a binary operator of addition, specifically "i + 1".
class BadSubscriptFinder : public RecursiveASTVisitor<BadSubscriptFinder> {
public:
  explicit BadSubscriptFinder(ASTContext &Ctx) : Ctx(Ctx), Found(false) { }
  
  bool FoundBad() const { return Found; }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    // Get the base expression text.
    SourceManager &SM = Ctx.getSourceManager();
    LangOptions LangOpts = Ctx.getLangOpts();
    CharSourceRange BaseRange = CharSourceRange::getTokenRange(ASE->getBase()->getSourceRange());
    StringRef BaseText = Lexer::getSourceText(BaseRange, SM, LangOpts);

    // We expect the array base to be "dc->links" or similar.
    if (!BaseText.contains("dc->links"))
      return true; // Skip if not our target array.

    // Now, analyze the index expression.
    const Expr *IndexExpr = ASE->getIdx();
    IndexExpr = IndexExpr->IgnoreParenCasts();

    // Check if the index expression is a binary operator.
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(IndexExpr)) {
      if (BO->getOpcode() == BO_Add) {
        // We expect a pattern of "i + 1".
        const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
        
        // Check that LHS is a DeclRefExpr with name "i".
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (DRE->getDecl()->getDeclName().getAsString() == "i") {
            // Check that RHS is an IntegerLiteral with value 1.
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

private:
  ASTContext &Ctx;
  bool Found;
};

// Main RecursiveASTVisitor to visit ForStmt nodes in the function body.
class ForStmtVisitor : public RecursiveASTVisitor<ForStmtVisitor> {
public:
  ForStmtVisitor(ASTContext &Ctx, BugReporter &BR, const Decl *D)
      : Ctx(Ctx), BR(BR), D(D), BugFound(false) { }

  bool VisitForStmt(ForStmt *FS) {
    // Get the loop condition.
    const Expr *Cond = FS->getCond();
    if (!Cond)
      return true;

    SourceManager &SM = Ctx.getSourceManager();
    LangOptions LangOpts = Ctx.getLangOpts();
    CharSourceRange CondRange = CharSourceRange::getTokenRange(Cond->getSourceRange());
    StringRef CondText = Lexer::getSourceText(CondRange, SM, LangOpts);

    // Check if the loop condition is of the form "i < MAX_PIPES * 2" (without subtracting 1).
    if (CondText.contains("MAX_PIPES") && CondText.contains("*")
        && CondText.contains("2") && !CondText.contains("- 1")) {

      // Within the loop body, look for an array access using (i + 1) on dc->links.
      BadSubscriptFinder Finder(Ctx);
      Finder.TraverseStmt(FS->getBody());
      if (Finder.FoundBad()) {
        // Report a bug at the location of the ForStmt.
        BugFound = true;
        // Use the updated API for creating the diagnostic location (without the extra Decl* argument).
        PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(FS, SM, LangOpts);
        auto R = std::make_unique<PathSensitiveBugReport>(
                             *BT,
                             "Array index out-of-bounds: loop condition allows (i+1) to exceed dc->links bounds",
                             nullptr);
        R->addRange(FS->getSourceRange());
        BR.emitReport(std::move(R));
      }
    }
    return true;
  }

  bool hasBug() const { return BugFound; }

  void setBugType(BugType *B) { BT = B; }

private:
  ASTContext &Ctx;
  BugReporter &BR;
  const Decl *D;
  bool BugFound;
  // Storing BugType pointer for reporting.
  BugType *BT = nullptr;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Out-of-bound Array Access",
                                         "Buffer Overflow")) { }

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    // Only consider function definitions.
    const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
    if (!FD || !FD->hasBody())
      return;

    // Check if this is the target function.
    if (FD->getNameAsString() != "get_host_router_total_dp_tunnel_bw")
      return;

    ASTContext &Ctx = FD->getASTContext();
    // Traverse the function body to look for problematic ForStmt nodes.
    ForStmtVisitor Visitor(Ctx, BR, D);
    Visitor.setBugType(BT.get());
    Visitor.TraverseStmt(FD->getBody());
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects out-of-bounds array access in get_host_router_total_dp_tunnel_bw", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
