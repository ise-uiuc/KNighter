#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>
#include <string>

using namespace clang;
using namespace ento;

// No additional program state is needed.

namespace {

/// A helper RecursiveASTVisitor to find calls to roundup_pow_of_two and check if
/// there is a guard condition that checks attr->max_entries against (1UL << 31).
class RoundupVisitor : public RecursiveASTVisitor<RoundupVisitor> {
public:
  RoundupVisitor(ASTContext &Ctx) : Context(Ctx), GuardFound(false) {}

  // Record source ranges of dangerous calls.
  std::vector<SourceRange> DangerousCallRanges;
  // Flag indicating whether an explicit guard check was found.
  bool GuardFound;

  // Visit if statements looking for a guard condition.
  bool VisitIfStmt(IfStmt *IfS) {
    Expr *Cond = IfS->getCond();
    if (!Cond)
      return true;

    // Get the source text for the condition.
    SourceManager &SM = Context.getSourceManager();
    LangOptions LangOpts = Context.getLangOpts();
    CharSourceRange CondRange = CharSourceRange::getTokenRange(Cond->getSourceRange());
    StringRef CondText = Lexer::getSourceText(CondRange, SM, LangOpts);

    // We look for the presence of both "max_entries" and "<<" (and "31")
    // in the condition text as a heuristic for the guard: if (attr->max_entries > 1UL << 31)
    if (CondText.contains("max_entries") &&
        CondText.contains("<<") &&
        CondText.contains("31"))
      GuardFound = true;

    return true;
  }

  // Visit call expressions looking for calls to roundup_pow_of_two.
  bool VisitCallExpr(CallExpr *Call) {
    // Try to get the callee declaration.
    if (FunctionDecl *FD = Call->getDirectCallee()) {
      StringRef CalleeName = FD->getNameInfo().getName().getAsString();
      if (CalleeName.equals("roundup_pow_of_two")) {
        DangerousCallRanges.push_back(Call->getSourceRange());
      }
    }
    return true;
  }

private:
  ASTContext &Context;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> { 
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker() : BT(new BugType(this, "Unchecked integer overflow risk", "Integer Overflow")) {}

   // Callback for checking the body of function definitions.
   void checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

};

void SAGenTestChecker::checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // Only interested in function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  // Check if this is the stack_map_alloc function.
  if (FD->getNameAsString() != "stack_map_alloc")
    return;

  ASTContext &Context = FD->getASTContext();
  // Use our RecursiveASTVisitor to analyze the function body.
  RoundupVisitor Visitor(Context);
  Visitor.TraverseDecl(const_cast<FunctionDecl*>(FD));

  // If we did not find any dangerous calls, nothing to report.
  if (Visitor.DangerousCallRanges.empty())
    return;

  // If a guard condition exists, then the call is deemed safe.
  if (Visitor.GuardFound)
    return;

  // Otherwise, for every dangerous call, report an error.
  for (const SourceRange &SR : Visitor.DangerousCallRanges) {
    // Create an error location using the beginning of the dangerous call range.
    PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(SR.getBegin(), BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(*BT, "Unchecked integer overflow risk in roundup_pow_of_two call", DLoc);
    Report->addRange(SR);
    BR.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential integer overflow in roundup_pow_of_two calls if size is not properly guarded", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
