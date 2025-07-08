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
#include "clang/Lex/Lexer.h"
#include "clang/AST/ASTContext.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnosticLocation.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// A simple RecursiveASTVisitor to inspect the body of stack_map_alloc.
class StackMapAllocVisitor : public RecursiveASTVisitor<StackMapAllocVisitor> {
public:
  StackMapAllocVisitor(const SourceManager &SM, const LangOptions &LangOpts)
      : SM(SM), LangOpts(LangOpts), FoundSafeCheck(false),
        FoundRoundingCall(false) {}

  // Visit If statements and check if the condition contains the proper check.
  bool VisitIfStmt(IfStmt *IfS) {
    if (Expr *Cond = IfS->getCond()) {
      // Get the source text of the condition.
      StringRef CondText = Lexer::getSourceText(
          CharSourceRange::getTokenRange(Cond->getSourceRange()), SM, LangOpts);
      // Look for "max_entries" and "1UL" and "<<".
      if (CondText.contains("max_entries") && CondText.contains("1UL") &&
          CondText.contains("<<"))
        FoundSafeCheck = true;
    }
    return true;
  }

  // Visit CallExpr nodes and check for calls to roundup_pow_of_two.
  bool VisitCallExpr(CallExpr *CallE) {
    StringRef CallText = Lexer::getSourceText(
        CharSourceRange::getTokenRange(CallE->getSourceRange()), SM, LangOpts);
    if (CallText.contains("roundup_pow_of_two")) {
      FoundRoundingCall = true;
      // Save the source range for potential bug reporting.
      RoundingCallRange = CallE->getSourceRange();
    }
    return true;
  }

  bool hasSafeCheck() const { return FoundSafeCheck; }
  bool hasRoundingCall() const { return FoundRoundingCall; }
  SourceRange getRoundingCallRange() const { return RoundingCallRange; }

private:
  const SourceManager &SM;
  const LangOptions &LangOpts;
  bool FoundSafeCheck;
  bool FoundRoundingCall;
  SourceRange RoundingCallRange;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked input to roundup_pow_of_two()",
                       "Integer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  void reportBug(const Decl *D, const SourceRange &Rng, BugReporter &BR,
                 AnalysisManager &Mgr) const;
};

void SAGenTestChecker::reportBug(const Decl *D, const SourceRange &Rng,
                                 BugReporter &BR,
                                 AnalysisManager &Mgr) const {
  const SourceManager &SM = BR.getSourceManager();
  PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(D, SM);
  // Generate a bug report using BasicBugReport (non-fatal)
  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "Unchecked input to roundup_pow_of_two() may overflow on 32-bit arches", Loc);
  Report->addRange(Rng);
  BR.emitReport(std::move(Report));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // We're only interested in the function "stack_map_alloc".
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (FD->getNameInfo().getName().getAsString() != "stack_map_alloc")
    return;

  // Get the body of the function.
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Get source manager and language options.
  const SourceManager &SM = BR.getSourceManager();
  const LangOptions &LangOpts = FD->getASTContext().getLangOpts();

  // Traverse the function body.
  StackMapAllocVisitor Visitor(SM, LangOpts);
  Visitor.TraverseStmt(const_cast<Stmt *>(Body));

  // If there is a call to roundup_pow_of_two, but no safe check before it,
  // report a bug.
  if (Visitor.hasRoundingCall() && !Visitor.hasSafeCheck()) {
    reportBug(D, Visitor.getRoundingCallRange(), BR, Mgr);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked input to roundup_pow_of_two() leading to potential overflows on 32-bit arches",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
