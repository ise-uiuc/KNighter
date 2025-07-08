#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/LangOptions.h"
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
// Replaced the removed header with the appropriate one that provides PathDiagnosticLocation.
#include "clang/StaticAnalyzer/Checkers/BugReporterVisitors.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <vector>
#include <string>
#include <memory> // Added for std::unique_ptr and std::make_unique

using namespace clang;
using namespace ento;

namespace {

// Visitor to traverse the body of gsm_cleanup_mux and record key call locations.
class GSMCleanupVisitor : public RecursiveASTVisitor<GSMCleanupVisitor> {
public:
  GSMCleanupVisitor(ASTContext &Ctx, const SourceManager &SM)
      : Ctx(Ctx), SM(SM), flushFound(false) {}

  // Record the source location of the flush call.
  SourceLocation flushLoc;
  // Record locations of potential guard calls.
  std::vector<SourceLocation> guardLocs;
  // Record locations of free operations on tx_ctrl_list/tx_data_list.
  std::vector<SourceLocation> freeLocs;
  bool flushFound;

  bool VisitCallExpr(const CallExpr *Call) {
    // Get source text for the call.
    SourceRange SR = Call->getSourceRange();
    LangOptions LangOpts = Ctx.getLangOpts();
    StringRef CallText = Lexer::getSourceText(CharSourceRange::getTokenRange(SR), SM, LangOpts);
    // Check for flush call.
    if (CallText.contains("tty_ldisc_flush")) {
      flushLoc = Call->getExprLoc();
      flushFound = true;
    }
    // Check for a guard call that acquires the tx_lock.
    if (CallText.contains("guard(spinlock_irqsave)") && CallText.contains("tx_lock")) {
      guardLocs.push_back(Call->getExprLoc());
    }
    // Check for freeing calls operating on tx_ctrl_list or tx_data_list.
    if ((CallText.contains("tx_ctrl_list") || CallText.contains("tx_data_list")) &&
        (CallText.contains("list_for_each_entry_safe") || CallText.contains("kfree"))) {
      freeLocs.push_back(Call->getExprLoc());
    }
    return true;
  }

private:
  ASTContext &Ctx;
  const SourceManager &SM;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
          "Missing Synchronization",
          "Missing lock acquisition for tx_ctrl_list/tx_data_list")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  // Helper function to report a bug at a given location.
  void reportUnsync(const Decl *D, const SourceLocation &Loc, BugReporter &BR) const;
};

void SAGenTestChecker::reportUnsync(const Decl *D, const SourceLocation &Loc, BugReporter &BR) const {
  PathDiagnosticLocation BugLoc = PathDiagnosticLocation::createBegin(D, BR.getSourceManager());
  auto R = std::make_unique<BasicBugReport>(*BT,
    "Use‐after‐free vulnerability: shared transmission queues are accessed without proper synchronization (missing guard for tx_lock)",
    BugLoc);
  R->addRange(D->getSourceRange());
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // Only interested in function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // Check if this is the target function "gsm_cleanup_mux".
  if (FD->getNameAsString() != "gsm_cleanup_mux")
    return;

  // Ensure the function has a body.
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = FD->getASTContext();
  const SourceManager &SM = BR.getSourceManager();

  // Traverse the AST of the function body.
  GSMCleanupVisitor Visitor(Ctx, SM);
  Visitor.TraverseStmt(const_cast<Stmt*>(Body));

  // We only perform our check if the flush call was seen.
  if (!Visitor.flushFound)
    return;

  // For each free operation recorded after flush, check if a guard call occurs between the flush and the free.
  for (const SourceLocation &FreeLoc : Visitor.freeLocs) {
    bool guardFound = false;
    for (const SourceLocation &GuardLoc : Visitor.guardLocs) {
      // Check if the guard call is between the flush and the free.
      if (SM.isBeforeInTranslationUnit(Visitor.flushLoc, GuardLoc) &&
          SM.isBeforeInTranslationUnit(GuardLoc, FreeLoc)) {
        guardFound = true;
        break;
      }
    }
    if (!guardFound) {
      // Report bug at the free location.
      reportUnsync(D, FreeLoc, BR);
      // Report only once per function.
      break;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing synchronization (guard for tx_lock) when freeing tx_ctrl_list/tx_data_list",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
