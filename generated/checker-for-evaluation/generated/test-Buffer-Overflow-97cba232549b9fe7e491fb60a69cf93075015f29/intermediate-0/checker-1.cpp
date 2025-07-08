#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// A RecursiveASTVisitor to search for the off-by-one bug pattern in a for-loop.
// NOTE: We now pass a BugReporter and ASTContext (instead of CheckerContext) to
// allow creation of a BasicBugReport.
class OffByOneVisitor : public RecursiveASTVisitor<OffByOneVisitor> {
public:
  OffByOneVisitor(BugReporter &BR, ASTContext &Ctx, const ForStmt *FS, const BugType *BT)
    : BR(BR), Ctx(Ctx), ForLoop(FS), BugReported(false), BT(BT) { }

  // Returns true if bug found.
  bool foundBug() const { return BugReported; }

  bool TraverseStmt(Stmt *S) {
    if (BugReported)
      return false; // stop early if bug has been reported
    return RecursiveASTVisitor<OffByOneVisitor>::TraverseStmt(S);
  }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    if (!ForLoop)
      return true;
    // Check if the subscript access is of the pattern: dc->links[i + 1]
    // First, check if the base expression is a MemberExpr with name "links".
    Expr *BaseExpr = ASE->getBase()->IgnoreParenCasts();
    if (const MemberExpr *ME = dyn_cast<MemberExpr>(BaseExpr)) {
      if (!ExprHasName(ME, "links", Ctx))
        return true;
    } else {
      return true;
    }

    // Now, check the index expression for (i + 1)
    Expr *IdxExpr = ASE->getIdx()->IgnoreParenCasts();
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(IdxExpr)) {
      if (BO->getOpcode() == BO_Add) {
        // Check that one side is the loop counter and the other is literal 1.
        const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

        const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
        const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(RHS);
        if (!DRE || !IL) {
          // try swapping sides
          DRE = dyn_cast<DeclRefExpr>(RHS);
          IL = dyn_cast<IntegerLiteral>(LHS);
        }
        if (DRE && IL) {
          // Check that the literal is 1.
          if (IL->getValue() == 1) {
            // Check if the referenced variable is the loop counter.
            // For the for-loop, we assume the counter variable is declared in the for-loop initializer.
            if (const DeclStmt *DS = dyn_cast_or_null<DeclStmt>(ForLoop->getInit())) {
              for (const auto *DI : DS->decls()) {
                if (const VarDecl *VD = dyn_cast<VarDecl>(DI)) {
                  if (VD == DRE->getDecl()) {
                    // We found that the array index uses the loop counter with an addition of 1.
                    BugReported = true;
                    reportBug(ASE);
                    break;
                  }
                }
              }
            }
          }
        }
      }
    }

    return true;
  }

private:
  BugReporter &BR;
  ASTContext &Ctx;
  const ForStmt *ForLoop;
  bool BugReported;
  const BugType *BT;

  void reportBug(const ArraySubscriptExpr *ASE) {
    // Create a location for the bug report.
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(ASE, BR.getSourceManager(), &Ctx);
    auto Report = std::make_unique<BasicBugReport>(
        *BT, "Off-by-one error: potential out-of-bound access in dc->links", Loc);
    Report->addRange(ASE->getSourceRange());
    BR.emitReport(std::move(Report));
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Out-of-bound Array Access", "Off-by-one Error")) { }

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                          BugReporter &BR) const {
  // Only interested in function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // Filter for the target function name
  if (FD->getNameAsString() != "get_host_router_total_dp_tunnel_bw")
    return;

  // Get the function body.
  if (const Stmt *Body = FD->getBody()) {
    // Traverse the body; particularly look for ForStmt nodes.
    for (const Stmt *S : Body->children()) {
      if (!S)
        continue;
      // Look for a ForStmt.
      if (const ForStmt *FS = dyn_cast<ForStmt>(S)) {
        // Analyze the loop condition.
        // Expected buggy loop condition: i < (MAX_PIPES * 2)
        if (const Expr *Cond = FS->getCond()) {
          Cond = Cond->IgnoreParenCasts();
          if (const BinaryOperator *CondBO = dyn_cast<BinaryOperator>(Cond)) {
            if (CondBO->getOpcode() == BO_LT) {
              // Check left-hand side is a DeclRefExpr (assumed loop variable)
              const Expr *LHS = CondBO->getLHS()->IgnoreParenCasts();
              const DeclRefExpr *LoopVar = dyn_cast<DeclRefExpr>(LHS);
              if (!LoopVar)
                continue;
              // Check right-hand side is a multiplication expression.
              const Expr *RHS = CondBO->getRHS()->IgnoreParenCasts();
              if (const BinaryOperator *MulBO = dyn_cast<BinaryOperator>(RHS)) {
                if (MulBO->getOpcode() == BO_Mul) {
                  // Use utility function ExprHasName to check if "MAX_PIPES" appears.
                  if (ExprHasName(MulBO->getLHS(), "MAX_PIPES", BR.getContext()) ||
                      ExprHasName(MulBO->getRHS(), "MAX_PIPES", BR.getContext())) {
                    // We suspect the loop condition is "i < (MAX_PIPES * 2)"
                    // Now traverse the loop body for array access using i + 1.
                    OffByOneVisitor Visitor(BR, FD->getASTContext(), FS, BT.get());
                    Visitor.TraverseStmt(const_cast<Stmt*>(FS->getBody()));
                    if (Visitor.foundBug())
                      return;
                  }
                }
              }
            }
          }
        }
      }
      // Also recursively look into children statements.
      for (const Stmt *Child : S->children()) {
        if (!Child)
          continue;
        if (const ForStmt *FS = dyn_cast<ForStmt>(Child)) {
          if (const Expr *Cond = FS->getCond()) {
            Cond = Cond->IgnoreParenCasts();
            if (const BinaryOperator *CondBO = dyn_cast<BinaryOperator>(Cond)) {
              if (CondBO->getOpcode() == BO_LT) {
                const Expr *LHS = CondBO->getLHS()->IgnoreParenCasts();
                const DeclRefExpr *LoopVar = dyn_cast<DeclRefExpr>(LHS);
                if (!LoopVar)
                  continue;
                const Expr *RHS = CondBO->getRHS()->IgnoreParenCasts();
                if (const BinaryOperator *MulBO = dyn_cast<BinaryOperator>(RHS)) {
                  if (MulBO->getOpcode() == BO_Mul) {
                    if (ExprHasName(MulBO->getLHS(), "MAX_PIPES", BR.getContext()) ||
                        ExprHasName(MulBO->getRHS(), "MAX_PIPES", BR.getContext())) {
                      OffByOneVisitor Visitor(BR, FD->getASTContext(), FS, BT.get());
                      Visitor.TraverseStmt(const_cast<Stmt*>(FS->getBody()));
                      if (Visitor.foundBug())
                        return;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bound access in dc->links due to an off-by-one error in loop conditions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
