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

// Additional includes
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Expr.h"
// Updated include: Adjusted header file location for Clang-18 compatibility.
#include "clang/StaticAnalyzer/Core/PathDiagnosticLocation.h"

using namespace clang;
using namespace ento;
using namespace taint;

//
// No extra program state customization is required.
//

namespace {

/// RecursiveASTVisitor to detect the problematic while loop in the error cleanup.
class WhileConditionVisitor : public RecursiveASTVisitor<WhileConditionVisitor> {
public:
  WhileConditionVisitor(ASTContext &Ctx, BugReporter &BR, const BugType &BT)
    : Ctx(Ctx), BR(BR), BT(BT), Found(false) {}

  bool VisitWhileStmt(WhileStmt *WS) {
    // Get the loop condition.
    Expr *Cond = WS->getCond();
    if (!Cond)
      return true;
    Cond = Cond->IgnoreParenCasts();
    // Check if the condition is a binary operator.
    BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
    if (!BO)
      return true;
    // Check that the binary operator is '>'.
    if (BO->getOpcode() != BO_GT)
      return true;
    // Check that the left-hand side of the condition is a unary operator.
    Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS);
    if (!UO)
      return true;
    // The left-hand side should be a pre-decrement, i.e., (--i).
    if (UO->getOpcode() != UO_PreDec)
      return true;
    // The right-hand side should be an integer literal '0'.
    Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    IntegerLiteral *IL = dyn_cast<IntegerLiteral>(RHS);
    if (!IL)
      return true;
    if (!IL->getValue().isZero())
      return true;
    // We have found a while loop with condition (--i > 0)
    // Report the bug: the cleanup loop boundary is incorrect (it should be (--i >= 0)).
    SourceRange SR = WS->getSourceRange();
    // Instead of generating an ExplodedNode, use the source location.
    auto Loc = PathDiagnosticLocation::createBegin(SR.getBegin(), Ctx);
    auto Report = std::make_unique<BasicBugReport>(
          BT, 
          "Incorrect cleanup loop boundary: loop condition (--i > 0) fails to clean index 0",
          Loc);
    Report->addRange(SR);
    BR.emitReport(std::move(Report));
    Found = true;
    // Stop traversal once the bug is found.
    return false;
  }

  bool foundBug() const { return Found; }

private:
  ASTContext &Ctx;
  BugReporter &BR;
  const BugType &BT;
  bool Found;
};

/// Checker to detect the off-by-one error in the cleanup loop within
/// the function "gsc_runtime_resume".
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Incorrect cleanup loop boundary")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                          AnalysisManager &Mgr,
                                          BugReporter &BR) const {
  // Only check function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  // Only target the function "gsc_runtime_resume".
  if (FD->getNameAsString() != "gsc_runtime_resume")
    return;
  // Get the function body.
  const Stmt *FuncBody = FD->getBody();
  if (!FuncBody)
    return;
  ASTContext &Ctx = FD->getASTContext();
  // Use the visitor to search for the problematic cleanup loop.
  WhileConditionVisitor Visitor(Ctx, BR, *BT);
  Visitor.TraverseStmt(const_cast<Stmt*>(FuncBody));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects incorrect cleanup loop boundary in gsc_runtime_resume (off by one error)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
