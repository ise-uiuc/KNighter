#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;

// No additional program state is needed for this checker.

namespace {

/// Helper function to check whether the source text of an expression contains
/// a given substring.
bool exprTextContains(const Expr *E, const llvm::StringRef Sub, const SourceManager &SM,
                      const LangOptions &LangOpts) {
  if (!E)
    return false;
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  return Text.contains(Sub);
}

/// Recursive visitor to traverse the body of a function and record
/// the source locations of a guard call (protecting tx_lock) and any kfree call
/// on tx_ctrl_list or tx_data_list.
class CleanupFunctionVisitor
    : public RecursiveASTVisitor<CleanupFunctionVisitor> {
public:
  CleanupFunctionVisitor(ASTContext &Ctx)
      : SM(Ctx.getSourceManager()), LangOpts(Ctx.getLangOpts()),
        GuardLoc(), FreeLoc() {}

  bool VisitCallExpr(CallExpr *CE) {
    // Check for a guard call that locks "tx_lock".
    // We look for a call expression that contains both "guard" and "tx_lock"
    if (exprTextContains(CE, "guard", SM, LangOpts) &&
        exprTextContains(CE, "tx_lock", SM, LangOpts)) {
      if (!GuardLoc.isValid())
        GuardLoc = CE->getBeginLoc();
    }
    // Check for a kfree call that frees "tx_ctrl_list" or "tx_data_list"
    if (exprTextContains(CE, "kfree", SM, LangOpts) &&
        (exprTextContains(CE, "tx_ctrl_list", SM, LangOpts) ||
         exprTextContains(CE, "tx_data_list", SM, LangOpts))) {
      if (!FreeLoc.isValid())
        FreeLoc = CE->getBeginLoc();
    }
    return true;
  }

  /// Returns the recorded guard call location.
  SourceLocation getGuardLoc() const { return GuardLoc.isValid() ? GuardLoc : SourceLocation(); }
  /// Returns the recorded free call location.
  SourceLocation getFreeLoc() const { return FreeLoc.isValid() ? FreeLoc : SourceLocation(); }

private:
  const SourceManager &SM;
  const LangOptions &LangOpts;
  SourceLocation GuardLoc;
  SourceLocation FreeLoc;
};

/// The checker class using the checkASTCodeBody callback.
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Race Condition: Missing lock",
                                         "Concurrency")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                        AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // We only care about function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  // Check if the function name is "gsm_cleanup_mux"
  if (!FD->getIdentifier() || FD->getName() != "gsm_cleanup_mux")
    return;
  
  // Get the body of the function.
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = FD->getASTContext();
  CleanupFunctionVisitor Visitor(Ctx);
  Visitor.TraverseStmt(const_cast<Stmt*>(Body));

  const SourceManager &SM = Ctx.getSourceManager();
  SourceLocation GuardLoc = Visitor.getGuardLoc();
  SourceLocation FreeLoc = Visitor.getFreeLoc();

  // If we found a free call on one of the tx lists.
  if (FreeLoc.isValid()) {
    // If no guard call was found or it appears after the free call, then report.
    bool ReportBug = false;
    if (!GuardLoc.isValid())
      ReportBug = true;
    else if (SM.isBeforeInTranslationUnit(FreeLoc, GuardLoc))
      ReportBug = true;

    if (ReportBug) {
      // Generate a bug report.
      SmallString<128> Buf;
      llvm::raw_svector_ostream OS(Buf);
      OS << "Shared tx list is freed without holding tx_lock "
            "in function 'gsm_cleanup_mux'";
      // Adjusted API: Removed the LangOptions parameter.
      PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(Body, SM);
      BR.emitReport(
          std::make_unique<BasicBugReport>(*BT, OS.str(), DLoc));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing locking (guard on tx_lock) in gsm_cleanup_mux causing potential race conditions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
