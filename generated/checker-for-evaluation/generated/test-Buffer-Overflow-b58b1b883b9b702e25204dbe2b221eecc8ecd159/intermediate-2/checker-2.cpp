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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include <functional>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// The checker only needs to register the ASTCodeBody callback.
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Potential iov_iter count underflow")) {}

  // Callback to analyze function bodies.
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  // Helper function: Checks if the given BinaryOperator is the subtraction assignment
  // of "iter->count -= shorten" by verifying that the LHS is a MemberExpr whose field name is "count"
  // and its base is a DeclRefExpr with the name "iter".
  bool isIterCountSubtraction(const BinaryOperator *BO) const {
    if (!BO)
      return false;
    // Check if operator is '-='.
    if (BO->getOpcode() != BO_SubAssign)
      return false;
    // Check LHS: should be a member expression.
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const MemberExpr *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return false;
    // Check that the member name is "count".
    if (ME->getMemberDecl()->getName().compare("count") != 0)
      return false;
    // Check that the base of the member is a DeclRefExpr named "iter".
    const Expr *BaseExpr = ME->getBase()->IgnoreParenCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(BaseExpr);
    if (!DRE)
      return false;
    if (DRE->getDecl()->getDeclName().getAsIdentifierInfo()->getName() != "iter")
      return false;
    return true;
  }

  // Helper: Checks if one of the parent statements is an if-statement whose condition text
  // contains both "shorten" and "iter->count". Returns true if found.
  bool hasProperBoundaryCheck(const Stmt *S, const ASTContext &Ctx) const {
    if (!S)
      return false;
    // Retrieve parent nodes by casting away const-ness since getParents is non-const.
    auto Parents = const_cast<ASTContext &>(Ctx).getParents(*S);
    for (const DynTypedNode &Node : Parents) {
      if (const IfStmt *IfS = Node.get<IfStmt>()) {
        const Expr *Cond = IfS->getCond();
        if (!Cond)
          continue;
        // Get SourceManager from non-const ASTContext.
        SourceManager &SM = const_cast<ASTContext &>(Ctx).getSourceManager();
        LangOptions LangOpts = Ctx.getLangOpts();
        CharSourceRange CondRange = CharSourceRange::getTokenRange(Cond->getSourceRange());
        std::string CondText = Lexer::getSourceText(CondRange, SM, LangOpts).str();
        if (CondText.find("shorten") != std::string::npos &&
            CondText.find("iter->count") != std::string::npos)
          return true;
      }
      if (const Stmt *ParentStmt = Node.get<Stmt>()) {
        if (hasProperBoundaryCheck(ParentStmt, Ctx))
          return true;
      }
    }
    return false;
  }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                          AnalysisManager &Mgr,
                                          BugReporter &BR) const {
  // Only analyze function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;
  
  // Check if this is the target function: "bch2_direct_IO_read".
  if (!FD->getNameInfo().getName().getAsString().compare("bch2_direct_IO_read"))
    ; // continue
  else
    return;

  // Retrieve the function body.
  const Stmt *FuncBody = FD->getBody();
  if (!FuncBody)
    return;

  // Use the utility function to find a BinaryOperator in the function body.
  const BinaryOperator *FoundBO = findSpecificTypeInChildren<BinaryOperator>(FuncBody);
  if (!FoundBO)
    return;
  
  // Walk through BinaryOperators in the AST looking for our target subtraction.
  // A simple recursive lambda walker.
  const BinaryOperator *TargetBO = nullptr;
  std::function<void(const Stmt*)> FindTarget = [&](const Stmt *S) {
    if (!S)
      return;
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (isIterCountSubtraction(BO))
        TargetBO = BO;
    }
    if (TargetBO)
      return;
    for (const Stmt *Child : S->children())
      FindTarget(Child);
  };
  FindTarget(FuncBody);

  // If no subtraction of iter->count is found, nothing to do.
  if (!TargetBO)
    return;

  // Now, check if there is an if-statement guarding this subtraction.
  // We look upward from the subtraction expression to check for an if-statement that has
  // a condition containing "shorten" and "iter->count"
  if (hasProperBoundaryCheck(TargetBO, FD->getASTContext()))
    return; // Proper boundary check present; no bug.

  // Otherwise, generate a bug report.
  const ASTContext &Ctx = FD->getASTContext();
  // In Clang-18, the createBegin function no longer takes LangOptions.
  PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(TargetBO,
                                                                     const_cast<ASTContext&>(Ctx).getSourceManager());
  // Use BasicBugReport constructor that takes BugType, description, and location.
  auto *R = new BasicBugReport(*BT,
                               "Subtraction of 'shorten' from 'iter->count' may underflow the count without a boundary check",
                               Loc);
  BR.EmitReport(R);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential iov_iter count underflow when subtracting from iter->count without checking against underflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
