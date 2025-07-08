#include "clang/AST/ASTContext.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
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
#include "clang/StaticAnalyzer/Core/PathDiagnostic/PathDiagnosticLocation.h"
#include <memory>
#include <string>

using namespace clang;
using namespace ento;

// Helper function that extracts source text from a statement and checks for the presence of a given name.
static bool doesStmtContain(const Stmt *S, StringRef Name,
                            const SourceManager &SM, const LangOptions &LangOpts) {
  if (!S)
    return false;
  CharSourceRange CharRange = CharSourceRange::getTokenRange(S->getSourceRange());
  StringRef Text = Lexer::getSourceText(CharRange, SM, LangOpts);
  return Text.contains(Name);
}

// Recursively searches the AST upward for an IfStmt that guards the subtraction.
// It returns true if any ancestor IfStmt has a condition that mentions both "shorten"
// and "iter->count" (which is considered a safe guard in this context).
static bool hasGuard(const Stmt *S, ASTContext &Context,
                     const SourceManager &SM, const LangOptions &LangOpts) {
  if (!S)
    return false;
  DynTypedNodeList Parents = Context.getParents(*S);
  for (const DynTypedNode &Node : Parents) {
    if (const IfStmt *IfS = Node.get<IfStmt>()) {
      const Expr *Cond = IfS->getCond();
      if (Cond &&
          doesStmtContain(Cond, "shorten", SM, LangOpts) &&
          doesStmtContain(Cond, "iter->count", SM, LangOpts))
        return true;
    }
    if (const Stmt *ParentStmt = Node.get<Stmt>()) {
      if (hasGuard(ParentStmt, Context, SM, LangOpts))
        return true;
    }
  }
  return false;
}

// AST visitor that looks for the unchecked subtraction pattern.
// The pattern we are looking for is a compound subtraction ("-=")
// on an expression that accesses iter->count, subtracting a computed value
// that involves the variable "shorten". If no appropriate guarding IfStmt
// is found in the ancestry of the subtraction, we report a bug.
class UnderflowVisitor : public RecursiveASTVisitor<UnderflowVisitor> {
  BugReporter &BR;
  ASTContext &Context;
  const BugType *BT;
  const SourceManager &SM;
  const LangOptions &LangOpts;

public:
  UnderflowVisitor(BugReporter &BR, ASTContext &Context, const BugType *BT)
      : BR(BR), Context(Context), BT(BT),
        SM(BR.getSourceManager()), LangOpts(Context.getLangOpts()) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO)
      return true;

    // Look for the compound subtraction operator ("-=").
    if (BO->getOpcode() != BO_SubAssign)
      return true;

    // Examine the left-hand side (LHS) to check if it is an access to "iter->count".
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const MemberExpr *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return true;
    // Check that the member name is "count".
    if (ME->getMemberDecl()->getNameAsString() != "count")
      return true;
    // Verify that the base of the member expression refers to "iter".
    const Expr *Base = ME->getBase()->IgnoreParenCasts();
    if (!Base)
      return true;
    StringRef BaseText = Lexer::getSourceText(
        CharSourceRange::getTokenRange(Base->getSourceRange()), SM, LangOpts);
    if (!BaseText.contains("iter"))
      return true;

    // Check the right-hand side (RHS) to see if it involves the variable "shorten".
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    if (!doesStmtContain(RHS, "shorten", SM, LangOpts))
      return true;

    // Use helper to determine if there is an enclosing IfStmt that guards against underflow.
    if (hasGuard(BO, Context, SM, LangOpts))
      return true; // Safe: the subtraction is guarded.

    // If no proper guard is found, report a bug.
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
        static_cast<const Stmt*>(BO), SM, LangOpts);
    // Using BasicBugReport instead of instantiating the abstract BugReport.
    auto Report = std::make_unique<BasicBugReport>(
        *BT,
        "Unchecked subtraction on iter->count may underflow", Loc);
    Report->addRange(BO->getSourceRange());
    BR.emitReport(std::move(Report));

    return true;
  }
  // Continue traversing the AST.
  bool VisitStmt(Stmt *S) { return true; }
};

// The checker class. It uses the ASTCodeBody callback to inspect the bodies
// of functions for the target bug pattern.
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked subtraction",
                                        "Underflow")) {}

  // This callback is invoked for every function that has a body.
  // We traverse the function's AST and look for the subtraction pattern.
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
    if (!FD || !FD->hasBody())
      return;
    UnderflowVisitor Visitor(BR, FD->getASTContext(), BT.get());
    Visitor.TraverseDecl(const_cast<FunctionDecl*>(FD));
  }
};

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked subtraction on iter->count that may underflow", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
