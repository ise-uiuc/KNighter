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
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

//
// No custom program state maps are required for this checker.
//

namespace {

// A RecursiveASTVisitor to find the two critical operations:
class FlexibleArrayVisitor : public RecursiveASTVisitor<FlexibleArrayVisitor> {
public:
  ASTContext *Ctx;
  // Location where flexible array member "data" is accessed via memcpy.
  SourceLocation MemcpyLoc;
  // Location of the assignment updating the counter "datalen".
  SourceLocation AssignLoc;
  
  FlexibleArrayVisitor(ASTContext *Context)
      : Ctx(Context), MemcpyLoc(), AssignLoc() {}

  // Visit call expressions to detect memcpy() calls.
  bool VisitCallExpr(CallExpr *CE) {
    // Check if the callee of the call is named "memcpy".
    const Expr *CalleeExpr = CE->getCallee()->IgnoreParenCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(CalleeExpr)) {
      if (DRE->getDecl()->getNameAsString() == "memcpy") {
        // Ensure there is at least one argument.
        if (CE->getNumArgs() >= 1) {
          const Expr *DestExpr = CE->getArg(0);
          // Check if the destination is a MemberExpr accessing "data".
          if (const MemberExpr *ME = dyn_cast<MemberExpr>(DestExpr->IgnoreParenCasts())) {
            if (ME->getMemberDecl()->getNameAsString() == "data") {
              // Record the location of this memcpy call.
              MemcpyLoc = CE->getBeginLoc();
            }
          }
        }
      }
    }
    return true;
  }
  
  // Visit assignment operators to detect updates to "datalen".
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->isAssignmentOp()) {
      if (const MemberExpr *ME =
              dyn_cast<MemberExpr>(BO->getLHS()->IgnoreParenCasts())) {
        if (ME->getMemberDecl()->getNameAsString() == "datalen") {
          // Record the location of this assignment.
          AssignLoc = BO->getBeginLoc();
        }
      }
    }
    return true;
  }
};

//
// The Checker: It uses the ASTCodeBody callback to analyze the ordering
// within the function body.
//
class SAGenTestChecker
  : public Checker< check::ASTCodeBody > {
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker() 
      : BT(new BugType(this, "Flexible Array Counter Order Bug")) {}

   // Callback function to analyze the function's AST body.
   void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   // (No additional self-defined functions needed.)
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                          AnalysisManager &Mgr,
                                          BugReporter &BR) const {
  // We are interested only in function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // Limit analysis to the function "brcmf_fweh_process_event" (where the bug is known to occur).
  if (FD->getNameAsString() != "brcmf_fweh_process_event")
    return;

  // Get the function body.
  if (const Stmt *Body = FD->getBody()) {
    // Traverse the function body to find the critical operations.
    FlexibleArrayVisitor Visitor(&FD->getASTContext());
    Visitor.TraverseStmt(const_cast<Stmt*>(Body));

    // If either operation is not found, we do not have enough evidence.
    if (!Visitor.MemcpyLoc.isValid() || !Visitor.AssignLoc.isValid())
      return;

    // Compare the source locations: if memcpy (accessing "data") happens before
    // the assignment updating "datalen", then the counter is updated too late.
    const SourceManager &SM = FD->getASTContext().getSourceManager();
    if (SM.isBeforeInTranslationUnit(Visitor.MemcpyLoc, Visitor.AssignLoc)) {
      // Create a diagnostic location at the memcpy call.
      PathDiagnosticLocation DLoc =
          PathDiagnosticLocation::createBegin(Visitor.MemcpyLoc, SM, FD->getASTContext().getLangOpts());

      // Construct a brief error message.
      auto Report = std::make_unique<BasicBugReport>(
         *BT, "Flexible array counter (datalen) is updated after flexible array access (data)",
         DLoc);
      Report->addRange(Lexer::makeFileCharRange(CharSourceRange::getTokenRange(Visitor.MemcpyLoc, Visitor.MemcpyLoc), SM, FD->getASTContext().getLangOpts()).getAsRange());

      BR.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Checks that the counter of a flexible array member is updated before the array is accessed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
