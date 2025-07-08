#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
// Removed the non-existent header: "clang/AST/ExprArraySubscriptExpr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
 
// No custom program state is needed for this checker.

namespace {

/// This RecursiveASTVisitor searches for array subscript expressions within
/// a ForStmt body whose index expression is a binary addition of the loop
/// variable and the constant 1.
class ArraySubscriptFinder : public RecursiveASTVisitor<ArraySubscriptFinder> {
public:
  bool BugFound;
  const VarDecl *LoopVar;

  ArraySubscriptFinder(const VarDecl *LV) : BugFound(false), LoopVar(LV) {}

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    // Get the index expression and remove any parens/casts.
    Expr *IdxExpr = ASE->getIdx()->IgnoreParenCasts();
    if (BinaryOperator *BO = dyn_cast<BinaryOperator>(IdxExpr)) {
      if (BO->getOpcode() == BO_Add) {
        Expr *LHS = BO->getLHS()->IgnoreParenCasts();
        Expr *RHS = BO->getRHS()->IgnoreParenCasts();
        if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (DRE->getDecl() == LoopVar) {
            // Check that the right-hand side is exactly the integer literal 1.
            if (IntegerLiteral *IL = dyn_cast<IntegerLiteral>(RHS)) {
              llvm::APInt LitVal = IL->getValue();
              if (LitVal == 1)
                BugFound = true;
            }
          }
        }
      }
    }
    return true;
  }
  // Continue traversing by default.
};

/// This RecursiveASTVisitor traverses the AST of a function and looks for
/// ForStmt nodes. It then verifies within the loop body whether an array
/// subscript expression of the form loop_variable + 1 is used.
class OffByOneVisitor : public RecursiveASTVisitor<OffByOneVisitor> {
  BugReporter &BR;
  const FunctionDecl *FD;
  const BugType *BT;
  
public:
  OffByOneVisitor(BugReporter &BR, const FunctionDecl *FD, const BugType *BT)
      : BR(BR), FD(FD), BT(BT) {}

  bool VisitForStmt(ForStmt *FS) {
    // Retrieve the loop initialization statement.
    DeclStmt *InitStmt = dyn_cast_or_null<DeclStmt>(FS->getInit());
    if (!InitStmt)
      return true;

    // Assume that the for statement declares a loop variable.
    const VarDecl *LoopVar = nullptr;
    for (const auto *DI : InitStmt->decls()) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DI)) {
        LoopVar = VD;
        break;
      }
    }
    if (!LoopVar)
      return true;

    // Traverse the body of the for loop to find an array subscript expression
    // using (loop variable + 1) as an index.
    ArraySubscriptFinder Finder(LoopVar);
    Finder.TraverseStmt(FS->getBody());
    if (Finder.BugFound) {
      // If found, report an off-by-one bug.
      SourceRange SR = FS->getSourceRange();
      PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
          FS, BR.getSourceManager(), FD->getASTContext());
      auto *Report = new BasicBugReport(
          *BT,
          "Off-by-one buffer overflow: loop iterates up to full bound while accessing element with (i+1)",
          Loc);
      Report->addRange(SR);
      BR.emitReport(std::unique_ptr<BugReport>(Report));
    }
    return true;
  }
  
  // Continue traversing other statements.
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Off-by-one buffer overflow", "Buffer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

  // No additional self-defined functions are needed.
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // We're only interested in the function "get_host_router_total_dp_tunnel_bw".
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
    if (FD->getNameAsString() != "get_host_router_total_dp_tunnel_bw")
      return;

    // Only traverse the body if it is available.
    if (FD->hasBody()) {
      OffByOneVisitor Visitor(BR, FD, BT.get());
      Visitor.TraverseDecl(const_cast<FunctionDecl*>(FD));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects off-by-one buffer overflows in loop iterations accessing array elements with an offset", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
