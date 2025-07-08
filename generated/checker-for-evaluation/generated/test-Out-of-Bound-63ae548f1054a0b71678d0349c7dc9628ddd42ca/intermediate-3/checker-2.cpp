#include "clang/AST/ASTContext.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>  // Added for std::vector

using namespace clang;
using namespace ento;

namespace {

// Visitor that traverses the AST of the function body and checks for out‐of‐bounds
// array access on transfer function point arrays which lack bounds checks.
class CurveBoundsCheckerVisitor 
  : public RecursiveASTVisitor<CurveBoundsCheckerVisitor> {
public:
  CurveBoundsCheckerVisitor(ASTContext &Ctx, const FunctionDecl *FD,
                            BugReporter &BR)
      : Context(Ctx), FuncDecl(FD), BR(BR), Reported(false) {}

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    // Get the base expression (the array part) without implicit casts.
    Expr *BaseExpr = ASE->getBase()->IgnoreImplicit();
    if (!BaseExpr)
      return true;

    // Get source text of the base expression.
    SourceManager &SM = Context.getSourceManager();
    LangOptions LangOpts = Context.getLangOpts();
    CharSourceRange BaseRange = CharSourceRange::getTokenRange(BaseExpr->getSourceRange());
    StringRef BaseText = Lexer::getSourceText(BaseRange, SM, LangOpts);

    // Check if the array access is for one of the suspicious arrays:
    // "tf_pts.red", "tf_pts.green", or "tf_pts.blue".
    if (!(BaseText.contains("tf_pts.red") ||
          BaseText.contains("tf_pts.green") ||
          BaseText.contains("tf_pts.blue")))
      return true;

    // Use ParentMapContext to traverse upward in the AST.
    bool HasBoundsCheck = false;
    ParentMapContext &PM = Context.getParentMapContext();

    // Convert the returned list to a mutable vector.
    std::vector<DynTypedNode> Parents(PM.getParents(*ASE).begin(), PM.getParents(*ASE).end());
    // Traverse upward, looking for an if-statement that compares with TRANSFER_FUNC_POINTS.
    while (!Parents.empty() && !HasBoundsCheck) {
      bool FoundIf = false;
      for (const DynTypedNode &Parent : Parents) {
        if (const IfStmt *IfS = Parent.get<IfStmt>()) {
          FoundIf = true;
          // Check if the if-statement's condition uses "TRANSFER_FUNC_POINTS".
          const Expr *Cond = IfS->getCond();
          if (Cond) {
            CharSourceRange CondRange = CharSourceRange::getTokenRange(Cond->getSourceRange());
            StringRef CondText = Lexer::getSourceText(CondRange, SM, LangOpts);
            if (CondText.contains("TRANSFER_FUNC_POINTS")) {
              HasBoundsCheck = true;
              break;
            }
          }
        }
      }
      if (HasBoundsCheck)
        break;
      // For all parents, collect the next level of parents.
      std::vector<DynTypedNode> NextParents;
      for (const DynTypedNode &Parent : Parents) {
        auto Ancestors = PM.getParents(Parent);
        NextParents.insert(NextParents.end(), Ancestors.begin(), Ancestors.end());
      }
      // Replace Parents with the new collection.
      Parents = std::move(NextParents);
    }

    // If no bounds-check is found and we haven't reported yet, report a bug.
    if (!HasBoundsCheck && !Reported) {
      Reported = true;
      PathDiagnosticLocation Loc =
          PathDiagnosticLocation::createBegin(ASE, SM);
      auto *LocalBT = new BugType(nullptr, "Potential out-of-bounds array access",
                                  "Array Bounds");
      // Use BasicBugReport to create a report based on the suggested API.
      auto R = std::make_unique<BasicBugReport>(*LocalBT,
          "Array subscript on transfer function point array is not protected by a bounds check using TRANSFER_FUNC_POINTS",
          Loc);
      R->addRange(ASE->getSourceRange());
      BR.emitReport(std::move(R));
    }

    return true;
  }

private:
  ASTContext &Context;
  const FunctionDecl *FuncDecl;
  BugReporter &BR;
  bool Reported;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Missing bounds check", "Array Bounds")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    // We only care about the function "cm_helper_translate_curve_to_hw_format".
    const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
    if (!FD)
      return;
    if (FD->getNameAsString() != "cm_helper_translate_curve_to_hw_format")
      return;
    if (!FD->hasBody())
      return;

    ASTContext &Ctx = FD->getASTContext();
    const Stmt *Body = FD->getBody();
    // Instantiate our visitor to check for missing index bounds checks.
    CurveBoundsCheckerVisitor Visitor(Ctx, FD, BR);
    Visitor.TraverseStmt(const_cast<Stmt*>(Body));
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing bounds check for index variable before array access", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
  CLANG_ANALYZER_API_VERSION_STRING;
