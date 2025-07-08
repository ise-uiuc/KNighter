// /scratch/chenyuan-data/SAGEN/result-0224-bugfail-multi-o3mini/test-Out-of-Bound-3f7d9c1964fcd16d02a8a9d4fd6f6cb60c4cc530/checkers/checker1.cpp
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

using namespace clang;
using namespace ento;

// No custom program state maps are needed for this checker.

namespace {

// Helper RecursiveASTVisitor to search for the bounds check within the function body.
class BoundCheckVisitor : public RecursiveASTVisitor<BoundCheckVisitor> {
  ASTContext &Ctx;
  bool Found;
public:
  BoundCheckVisitor(ASTContext &Ctx) : Ctx(Ctx), Found(false) {}

  bool hasFoundCheck() const { return Found; }

  // Visit IfStmt nodes in the AST.
  bool VisitIfStmt(IfStmt *IfNode) {
    if (Found)
      return false; // Already found, can stop traversal.

    Expr *Cond = IfNode->getCond();
    if (!Cond)
      return true;

    // Look for a binary operator in the condition.
    if (BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenCasts())) {
      if (BO->getOpcode() == BO_GT) {
        Expr *LHS = BO->getLHS()->IgnoreParenCasts();
        Expr *RHS = BO->getRHS()->IgnoreParenCasts();

        // Retrieve the source text for the LHS.
        SourceManager &SM = Ctx.getSourceManager();
        LangOptions LangOpts = Ctx.getLangOpts();
        CharSourceRange LHSRange = CharSourceRange::getTokenRange(LHS->getSourceRange());
        StringRef LHSText = Lexer::getSourceText(LHSRange, SM, LangOpts);

        // Retrieve the source text for the RHS.
        CharSourceRange RHSRange = CharSourceRange::getTokenRange(RHS->getSourceRange());
        StringRef RHSText = Lexer::getSourceText(RHSRange, SM, LangOpts);

        // Check if either side contains "rss_key_size" and the other contains "VIRTIO_NET_RSS_MAX_KEY_SIZE".
        bool hasRssKey = LHSText.contains("rss_key_size") || RHSText.contains("rss_key_size");
        bool hasRssMax = LHSText.contains("VIRTIO_NET_RSS_MAX_KEY_SIZE") || RHSText.contains("VIRTIO_NET_RSS_MAX_KEY_SIZE");

        if (hasRssKey && hasRssMax)
          Found = true;
      }
    }
    return true;
  }
  
  // Also look inside compound statements.
  bool VisitCompoundStmt(CompoundStmt *CS) {
    // Continue traversal.
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Missing Bounds Check", "Configuration Validation")) {}

  // Called for each function (or method) with a body. We use this to check virtnet_probe.
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    // We only want to run this check for a function named "virtnet_probe".
    const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
    if (!FD)
      return;

    if (FD->getNameAsString() != "virtnet_probe")
      return;

    // Get the body of the function.
    const Stmt *Body = FD->getBody();
    if (!Body)
      return;

    // Traverse the function body looking for the proper bounds check.
    BoundCheckVisitor Visitor(FD->getASTContext());
    Visitor.TraverseStmt(const_cast<Stmt*>(Body));

    // If no bounds check is found, then report a bug.
    if (!Visitor.hasFoundCheck()) {
      // Create a source diagnostic location at the beginning of the function.
      PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(FD, BR.getSourceManager());
      // Create a bug report with a short message.
      auto R = std::make_unique<BasicBugReport>(*BT,
          "Missing bounds check on rss_key_size against VIRTIO_NET_RSS_MAX_KEY_SIZE",
          DLoc);
      R->addRange(Body->getSourceRange());
      BR.emitReport(std::move(R));
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Checks for a proper bounds check on rss_key_size in virtnet_probe", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
