#include "clang/AST/ASTContext.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
// Use the correct header for PathDiagnosticLocation.
#include "clang/StaticAnalyzer/Core/PathDiagnostic/PathDiagnosticLocation.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

/// Helper function to check recursively whether a statement is guarded by an if‐condition 
/// that tests the controlling flag "from_cancel". This function uses the ASTContext’s
/// parent mechanism.
bool isGuardedByFromCancel(Stmt *S, ASTContext &Ctx) {
  ParentMapContext &PMContext = Ctx.getParentMapContext();
  // Get the immediate parents of S.
  auto Parents = PMContext.getParents(*S);
  if (Parents.empty())
    return false;
  for (const DynTypedNode &ParentNode : Parents) {
    if (const IfStmt *IfS = ParentNode.get<IfStmt>()) {
      if (const Expr *Cond = IfS->getCond()) {
        SourceManager &SM = Ctx.getSourceManager();
        LangOptions LangOpts = Ctx.getLangOpts();
        // Get the source text for the condition.
        CharSourceRange CondRange = CharSourceRange::getTokenRange(Cond->getSourceRange());
        StringRef CondText = Lexer::getSourceText(CondRange, SM, LangOpts);
        if (CondText.contains("from_cancel"))
          return true;
      }
    }
    // If the parent is a statement, check recursively.
    if (const Stmt *ParentStmt = ParentNode.get<Stmt>()) {
      // Use const_cast because our function takes a non-const pointer.
      if (isGuardedByFromCancel(const_cast<Stmt*>(ParentStmt), Ctx))
        return true;
    }
  }
  return false;
}

/// Visitor to traverse the body of __flush_work and detect unguarded shared memory reads.
class FlushWorkVisitor : public RecursiveASTVisitor<FlushWorkVisitor> {
  ASTContext &Ctx;
  BugReporter &BR;
  const BugType *BT;
public:
  FlushWorkVisitor(ASTContext &Ctx, BugReporter &BR, const BugType *BT)
    : Ctx(Ctx), BR(BR), BT(BT) {}

  bool VisitUnaryOperator(UnaryOperator *UO) {
    // We are interested in dereference expressions.
    if (UO->getOpcode() != UO_Deref)
      return true;

    Expr *SubExpr = UO->getSubExpr()->IgnoreImplicit();
    if (CallExpr *CE = dyn_cast<CallExpr>(SubExpr)) {
      // Check if the call is to 'work_data_bits'
      Expr *CalleeExpr = CE->getCallee()->IgnoreImplicit();
      if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(CalleeExpr)) {
        if (DRE->getDecl()->getNameAsString() == "work_data_bits") {
          // We found a read of work->data from *work_data_bits(work)
          // Now check if this read is guarded by an if-statement that checks 'from_cancel'
          if (!isGuardedByFromCancel(UO, Ctx)) {
            // Pass the statement itself instead of a pointer.
            PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(*UO, Ctx.getSourceManager(), Ctx.getLangOpts());
            auto R = std::make_unique<BasicBugReport>(
                *BT, "Shared memory read unguarded by from_cancel check", DLoc);
            R->addRange(UO->getSourceRange());
            BR.emitReport(std::move(R));
          }
        }
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this,
      "Shared memory read unguarded by from_cancel check",
      "Synchronization")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                          AnalysisManager &Mgr,
                                          BugReporter &BR) const {
  // We only want to inspect function definitions.
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
    // Check if the function name is "__flush_work"
    if (FD->getNameAsString() != "__flush_work")
      return;
    if (!FD->hasBody())
      return;

    ASTContext &Ctx = FD->getASTContext();
    Stmt *Body = FD->getBody();

    // Use the FlushWorkVisitor to traverse the function body.
    FlushWorkVisitor Visitor(Ctx, BR, BT.get());
    Visitor.TraverseStmt(Body);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unguarded shared memory read in __flush_work", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
