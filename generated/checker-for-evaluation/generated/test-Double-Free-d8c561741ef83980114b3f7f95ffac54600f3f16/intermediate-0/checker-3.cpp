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

// Additional required includes.
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

/// A RecursiveASTVisitor to traverse the function body of
/// hws_send_ring_create_sq and locate calls to the wrong cleanup function.
class HWSCallVisitor : public RecursiveASTVisitor<HWSCallVisitor> {
  BugReporter &BR;
  const BugType *BT;
  // Flag to ensure we report only once per function body.
  bool Reported;
  const LangOptions &LO;
public:
  HWSCallVisitor(BugReporter &br, const BugType *bt, const LangOptions &LangOpts)
      : BR(br), BT(bt), Reported(false), LO(LangOpts) {}

  bool VisitCallExpr(CallExpr *CE) {
    if (Reported)
      return true;

    // Retrieve the callee function declaration.
    if (const FunctionDecl *Callee = CE->getDirectCallee()) {
      // Check if the call expression is to hws_send_ring_close_sq.
      if (Callee->getNameAsString() == "hws_send_ring_close_sq") {
        // Report the bug at the location of the call.
        SourceLocation Loc = CE->getBeginLoc();
        PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(CE, BR.getSourceManager(), LO);
        auto Report = std::make_unique<BasicBugReport>(
            *BT, "Incorrect cleanup: hws_send_ring_close_sq() used in error path may lead to double free", DLoc);
        Report->addRange(CE->getSourceRange());
        BR.emitReport(std::move(Report));
        Reported = true;
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() 
      : BT(new BugType(this, "Double Free: Incorrect Cleanup Usage",
                       "Resource Management")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // We are only interested in function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // We target the function "hws_send_ring_create_sq".
  if (FD->getNameAsString() != "hws_send_ring_create_sq")
    return;

  // Make sure the function has a body.
  if (const Stmt *Body = FD->getBody()) {
    HWSCallVisitor Visitor(BR, BT.get(), FD->getASTContext().getLangOpts());
    Visitor.TraverseStmt(const_cast<Stmt *>(Body));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of the incorrect cleanup function (hws_send_ring_close_sq) "
      "in the error path of hws_send_ring_create_sq which may lead to double free", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
