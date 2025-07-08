#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/PathDiagnosticLocation.h"
#include "llvm/Support/raw_ostream.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: Check if an expression is a MemberExpr accessing a field with a given name.
static bool hasMemberName(const Expr *E, const std::string &Name) {
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts()))
    return ME->getMemberNameInfo().getName().getAsString() == Name;
  return false;
}

// Helper: Check if a CallExpr is a call to a function with a given name.
// It checks the callee's DeclRefExpr.
static bool isCallToFunction(const CallExpr *CE, const std::string &FuncName) {
  const Expr *CalleeExpr = CE->getCallee()->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(CalleeExpr))
    return DRE->getDecl()->getNameAsString() == FuncName;
  return false;
}

// A recursive traversal helper to simulate the dynamic order of execution in the function.
// It walks the statements in pre-order (i.e. textual order) and tracks whether an assignment
// to "datalen" (the counter) has been encountered.
// If a memcpy call accessing the flexible array "data" is found before any such assignment,
// then it records the offending statement in BugStmt and returns true.
static bool traverseStmt(const Stmt *S, bool &DatalenAssigned,
                         const ASTContext &Ctx, const LangOptions &LangOpts,
                         const SourceManager &SM, const FunctionDecl *FD,
                         const Stmt *&BugStmt) {
  if (!S)
    return false;

  // Check if this statement is an assignment.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      if (hasMemberName(LHS, "datalen")) {
        // We encountered an assignment to the counter.
        DatalenAssigned = true;
      }
    }
  }

  // Check if this statement is a memcpy() call.
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (isCallToFunction(CE, "memcpy")) {
      // Verify that the destination argument is a reference to flexible array member "data".
      // memcpy's first argument is the destination.
      if (CE->getNumArgs() > 0) {
        const Expr *DestExpr = CE->getArg(0)->IgnoreParenCasts();
        if (hasMemberName(DestExpr, "data")) {
          // If "datalen" assignment has not yet been encountered,
          // we have a bug: the flexible array is accessed before the counter update.
          if (!DatalenAssigned) {
            BugStmt = S;
            return true;
          }
        }
      }
    }
  }

  // Recursively traverse children in the order they appear.
  for (const Stmt *Child : S->children()) {
    if (traverseStmt(Child, DatalenAssigned, Ctx, LangOpts, SM, FD, BugStmt))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Flexible array accessed before counter update")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

  // No additional callbacks needed.
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                          AnalysisManager &Mgr,
                                          BugReporter &BR) const {
  // We are interested only in the function "brcmf_fweh_process_event".
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  if (FD->getNameAsString() != "brcmf_fweh_process_event")
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Set up the SourceManager and language options.
  ASTContext &Ctx = FD->getASTContext();
  const LangOptions &LangOpts = Ctx.getLangOpts();
  const SourceManager &SM = Ctx.getSourceManager();

  // Traverse the function body in a pre-order fashion.
  bool DatalenAssigned = false;
  const Stmt *BugStmt = nullptr;
  if (!traverseStmt(Body, DatalenAssigned, Ctx, LangOpts, SM, FD, BugStmt))
    return;

  // Report the bug if found.
  if (BugStmt) {
    PathDiagnosticLocation BugLoc = PathDiagnosticLocation::createBegin(BugStmt, SM, LangOpts);
    // Create a simple bug report.
    auto *RDD = new BasicBugReport(
        *BT,
        "Flexible array accessed before counter update",
        BugLoc);
    RDD->addRange(BugStmt->getSourceRange());
    BR.emitReport(std::unique_ptr<BugReport>(RDD));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects when a flexible array is accessed (via memcpy to 'data') before updating its counter ('datalen')",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
