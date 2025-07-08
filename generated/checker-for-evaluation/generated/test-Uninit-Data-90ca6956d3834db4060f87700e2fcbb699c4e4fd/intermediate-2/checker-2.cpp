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
#include "clang/AST/Attr.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/PathDiagnosticLocation.h" // Updated header for PathDiagnosticLocation

using namespace clang;
using namespace ento;
using namespace taint;

//
// This checker detects auto-free pointer declarations that are not
// explicitly initialized to NULL.  For pointers declared with an attribute
// like __free(kfree), an initializer must be provided and it must evaluate to 0.
// Otherwise, the cleanup code may attempt to free an uninitialized (garbage) pointer,
// leading to undefined behavior or a crash.
//

namespace {

// A recursive AST visitor that examines all local variable declarations in a function body.
class AutoFreeVarDeclVisitor : public RecursiveASTVisitor<AutoFreeVarDeclVisitor> {
  BugReporter &BR;
  AnalysisManager &Mgr;
  const BugType *BT;
public:
  AutoFreeVarDeclVisitor(BugReporter &br, AnalysisManager &mgr, const BugType *bt)
    : BR(br), Mgr(mgr), BT(bt) {}

  bool VisitVarDecl(VarDecl *VD) {
    // Consider only pointer types.
    if (!VD->getType()->isPointerType())
      return true;
    
    // Only consider local variables (e.g., those declared inside function bodies).
    if (!VD->isLocalVarDecl())
      return true;

    // Retrieve the source text for the entire declaration.
    const SourceManager &SM = BR.getSourceManager();
    LangOptions LangOpts = Mgr.getLangOpts();
    SourceRange SR = VD->getSourceRange();
    StringRef DeclText = Lexer::getSourceText(CharSourceRange::getTokenRange(SR), SM, LangOpts);

    // Look for the auto-cleanup attribute pattern "__free(kfree)".
    if (!DeclText.contains("__free(kfree)"))
      return true;

    // If no initializer is provided, the pointer is uninitialized.
    if (!VD->hasInit()) {
      PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(VD, SM);
      BugReport *R = new BasicBugReport(*BT, "Auto-free pointer not initialized to NULL", Loc);
      R->addRange(VD->getSourceRange());
      BR.emitReport(R);
      return true;
    }

    // If an initializer is present, attempt to evaluate it to an integer constant.
    Expr *Init = VD->getInit();
    Expr::EvalResult EvalResult;
    if (Init->EvaluateAsInt(EvalResult, VD->getASTContext())) {
      llvm::APSInt Val = EvalResult.Val.getInt();
      if (Val != 0) {
        PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(VD, SM);
        BugReport *R = new BasicBugReport(*BT, "Auto-free pointer not initialized to NULL", Loc);
        R->addRange(VD->getSourceRange());
        BR.emitReport(R);
      }
    }
    // If the initializer cannot be evaluated to a constant integer, do not report.
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> { 
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker() 
     : BT(new BugType(this, "Auto-Free Pointer Initialization", "Memory Initialization")) {}

   // This callback is invoked for each function or method with a body.
   void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
     if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
       if (!FD->hasBody())
         return;
       // Traverse the function body to inspect all VarDecls.
       AutoFreeVarDeclVisitor Visitor(BR, Mgr, BT.get());
       Visitor.TraverseStmt(FD->getBody());
     }
   }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects auto-free pointers not initialized to NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
