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
#include "clang/AST/ASTContext.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
// Updated header include based on Clang-18 API changes.
#include "clang/StaticAnalyzer/Core/PathDiagnostic/PathDiagnosticLocation.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// A RecursiveASTVisitor that looks for array subscript expressions using one of the
// transfer function color arrays ("tf_pts.red", "tf_pts.green", "tf_pts.blue")
// and checks that there is an enclosing bounds-check using "TRANSFER_FUNC_POINTS".
class ArraySubscriptVisitor : public RecursiveASTVisitor<ArraySubscriptVisitor> {
  ASTContext &Context;
  BugReporter &BR;
  const BugType *BT;
public:
  ArraySubscriptVisitor(ASTContext &Ctx, BugReporter &R, const BugType *BugTy)
    : Context(Ctx), BR(R), BT(BugTy) {}

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    // Get the base expression of the array access.
    Expr *BaseExpr = ASE->getBase()->IgnoreParenImpCasts();
    if (!BaseExpr)
      return true;
    
    // Get the source text of the base expression.
    const SourceManager &SM = Context.getSourceManager();
    const LangOptions &LangOpts = Context.getLangOpts();
    CharSourceRange BaseRange = CharSourceRange::getTokenRange(BaseExpr->getSourceRange());
    StringRef BaseText = Lexer::getSourceText(BaseRange, SM, LangOpts);
    
    // Check if the base text corresponds to one of the target color arrays.
    if (!(BaseText.contains("tf_pts.red") ||
          BaseText.contains("tf_pts.green") ||
          BaseText.contains("tf_pts.blue")))
      return true; // Not our interest.

    // Now, walk upward in the AST using the parents API to see if there is any IfStmt
    // whose condition contains the string "TRANSFER_FUNC_POINTS".
    bool HasBoundsCheck = false;
    // Starting from the current ArraySubscriptExpr.
    llvm::SmallVector<DynTypedNode, 8> Worklist;
    Worklist.push_back(DynTypedNode::create(*ASE));
    while (!Worklist.empty() && !HasBoundsCheck) {
      DynTypedNode Node = Worklist.pop_back_val();
      // Get parents from the ASTContext.
      auto Parents = Context.getParents(Node);
      for (const DynTypedNode &Parent : Parents) {
        // If parent is an IfStmt, test its condition.
        if (const IfStmt *IfS = Parent.get<IfStmt>()) {
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
        // Add the parent node to the worklist to continue upward traversal.
        Worklist.push_back(Parent);
      }
    }
    
    // If no enclosing bounds check was found, report a bug.
    if (!HasBoundsCheck) {
      // Report at the location of the array subscript operator.
      SourceLocation Loc = ASE->getExprLoc();
      PathDiagnosticLocation bugLoc = PathDiagnosticLocation::createBegin(ASE, SM, LangOpts);
      auto Report = std::make_unique<BasicBugReport>(
                      *BT,
                      "Missing bounds check against TRANSFER_FUNC_POINTS for transfer function array access",
                      bugLoc);
      Report->addRange(ASE->getSourceRange());
      BR.emitReport(std::move(Report));
    }
    
    return true;
  }
  
  // We want to traverse all nodes.
  bool TraverseStmt(Stmt *S) {
    return RecursiveASTVisitor<ArraySubscriptVisitor>::TraverseStmt(S);
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Missing array bounds check", "Array bounds error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // Only process function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  
  // Check that the function's name is "cm_helper_translate_curve_to_hw_format"
  if (FD->getNameAsString() != "cm_helper_translate_curve_to_hw_format")
    return;
  
  // Get the body of the function.
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;
  
  // Create our visitor to look for array subscript expressions that index transfer function arrays.
  ArraySubscriptVisitor Visitor(FD->getASTContext(), BR, BT.get());
  Visitor.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Checks for missing bounds checks on transfer function array accesses", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
