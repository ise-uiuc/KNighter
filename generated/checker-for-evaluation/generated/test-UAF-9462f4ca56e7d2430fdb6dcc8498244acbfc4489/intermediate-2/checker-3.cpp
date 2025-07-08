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

// Removed the dependency on the utility header; we implement our own helper.
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"

// The header providing PathDiagnosticLocation is typically available via BugReporter.h
// but if not, you may need to adjust the include as per your Clang version.
// #include "clang/StaticAnalyzer/Core/PathDiagnostic.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Visitor that traverses the function body of gsm_cleanup_mux to
// detect whether a guard call for tx_lock is present between the call
// to tty_ldisc_flush and the freeing loops (calls to kfree/kvfree).
class GSMCleanupVisitor : public RecursiveASTVisitor<GSMCleanupVisitor> {
public:
  // Only the ASTContext is needed.
  GSMCleanupVisitor(ASTContext &Ctx)
    : Ctx(Ctx), FlushLoc(), GuardLoc(), FirstKfreeLoc() {}

  bool TraverseStmt(Stmt *S) {
    if (!S)
      return true;
    RecursiveASTVisitor<GSMCleanupVisitor>::TraverseStmt(S);
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    // Get the origin expression (if available) for proper source text analysis.
    const Expr *Origin = CE;
    // Obtain the source text of the callee.
    const Expr *CalleeExpr = CE->getCallee();
    if (!CalleeExpr)
      return true;
    StringRef CalleeText = Lexer::getSourceText(
        CharSourceRange::getTokenRange(CalleeExpr->getSourceRange()),
        Ctx.getSourceManager(), Ctx.getLangOpts());
    // Check if this is a call to tty_ldisc_flush.
    if (CalleeText.contains("tty_ldisc_flush")) {
      FlushLoc = CE->getBeginLoc();
    }
    
    // Check for guard calls. We expect the call to be something like guard(spinlock_irqsave)
    // and its argument to contain "tx_lock".
    if (CalleeText.contains("guard")) {
      // Now, check the arguments.
      for (unsigned i = 0, e = CE->getNumArgs(); i < e; i++) {
        const Expr *Arg = CE->getArg(i);
        if (!Arg)
          continue;
        if (exprHasName(Arg, "tx_lock", Ctx)) {
          if (GuardLoc.isInvalid() ||
              Ctx.getSourceManager().isBeforeInTranslationUnit(CE->getBeginLoc(), GuardLoc))
            GuardLoc = CE->getBeginLoc();
        }
      }
    }
    
    // Check for calls to kfree or kvfree.
    if (CalleeText.contains("kfree") || CalleeText.contains("kvfree")) {
      if (FirstKfreeLoc.isInvalid() ||
          Ctx.getSourceManager().isBeforeInTranslationUnit(CE->getBeginLoc(), FirstKfreeLoc))
        FirstKfreeLoc = CE->getBeginLoc();
    }
    
    return true;
  }

  // Returns true if a guard call for tx_lock was found between the flush and first free.
  bool hasProperGuard() const {
    if (FlushLoc.isInvalid() || FirstKfreeLoc.isInvalid())
      return false;
    const SourceManager &SM = Ctx.getSourceManager();
    if (GuardLoc.isValid() &&
        SM.isBeforeInTranslationUnit(FlushLoc, GuardLoc) &&
        SM.isBeforeInTranslationUnit(GuardLoc, FirstKfreeLoc))
      return true;
    return false;
  }

private:
  // Helper function to check if the expression's source text contains a given name.
  static bool exprHasName(const Expr *E, StringRef Name, ASTContext &Ctx) {
    CharSourceRange CSR = CharSourceRange::getTokenRange(E->getSourceRange());
    StringRef Text = Lexer::getSourceText(CSR, Ctx.getSourceManager(), Ctx.getLangOpts());
    return Text.contains(Name);
  }

  ASTContext &Ctx;
  SourceLocation FlushLoc;      // Location of tty_ldisc_flush
  SourceLocation GuardLoc;      // Location of guard(spinlock_irqsave)(tx_lock)
  SourceLocation FirstKfreeLoc; // Earliest location of a free (kfree/kvfree)
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Use-after-free due to missing spin lock guard",
                     "Synchronization error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // Only inspect function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;
  // Only target the function gsm_cleanup_mux.
  if (FD->getNameAsString() != "gsm_cleanup_mux")
    return;

  ASTContext &Ctx = FD->getASTContext();
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Use our visitor to traverse the function body.
  GSMCleanupVisitor Visitor(Ctx);
  Visitor.TraverseStmt(const_cast<Stmt*>(Body));

  // Check if the free calls are present and if the proper guard call is missing.
  if (!Visitor.hasProperGuard()) {
    // Use the start of the body as the bug location.
    // Create a PathDiagnosticLocation from the body instead of a SourceLocation.
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(Body, Ctx.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, "Use‐after‐free: Missing spin lock guard on tx_lock in gsm_cleanup_mux", Loc);
    // Use a SourceRange instead of CharSourceRange.
    Report->addRange(SourceRange(Body->getBeginLoc(), Body->getBeginLoc()));
    BR.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use‐after‐free due to missing spin lock guard on tx_lock in gsm_cleanup_mux",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
