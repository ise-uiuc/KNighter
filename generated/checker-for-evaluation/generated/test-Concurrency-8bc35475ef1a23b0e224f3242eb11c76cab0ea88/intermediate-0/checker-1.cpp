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
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state maps are needed for this checker.

namespace {

/// Helper function: Check if statement S is within an IfStmt whose condition text
/// contains "from_cancel".  We use the ASTContext's parent retrieval mechanism
/// and Lexer::getSourceText to extract the condition text.
bool isGuardedByFromCancel(const Stmt *S, ASTContext &Ctx, const SourceManager &SM,
                           const LangOptions &LangOpts) {
  // Use a worklist to traverse upward.
  SmallVector<const Stmt *, 8> WorkList;
  WorkList.push_back(S);

  while (!WorkList.empty()) {
    const Stmt *Curr = WorkList.pop_back_val();
    // Get all parents of the current statement.
    auto Parents = Ctx.getParents(*Curr);
    for (const auto &Node : Parents) {
      if (const IfStmt *IfS = Node.get<IfStmt>()) {
        if (const Expr *Cond = IfS->getCond()) {
          // Get source text for the condition.
          CharSourceRange CondRange = CharSourceRange::getTokenRange(Cond->getSourceRange());
          StringRef CondText = Lexer::getSourceText(CondRange, SM, LangOpts);
          if (CondText.contains("from_cancel"))
            return true;
        }
      }
      // If the parent node is also a statement, add it to the worklist.
      if (const Stmt *ParentStmt = Node.get<Stmt>())
        WorkList.push_back(ParentStmt);
    }
  }
  return false;
}

/// AST visitor to traverse the body of __flush_work to locate dereferences of
/// work_data_bits() that are not conditionally guarded by a test on "from_cancel".
class FlushWorkVisitor : public RecursiveASTVisitor<FlushWorkVisitor> {
  ASTContext &Context;
  BugReporter &BR;
  const BugType *BT;
  const SourceManager &SM;
  const LangOptions &LangOpts;

public:
  FlushWorkVisitor(ASTContext &Ctx, BugReporter &BR, const BugType *BT)
      : Context(Ctx), BR(BR), BT(BT),
        SM(Ctx.getSourceManager()), LangOpts(Ctx.getLangOpts()) {}

  bool VisitUnaryOperator(UnaryOperator *UO) {
    // Look for dereference operator.
    if (UO->getOpcode() != UO_Deref)
      return true;

    // Check if the operand is a call expression.
    Expr *SubExpr = UO->getSubExpr()->IgnoreParenImpCasts();
    CallExpr *CE = dyn_cast<CallExpr>(SubExpr);
    if (!CE)
      return true;

    // Check if the called function is "work_data_bits".
    if (FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getNameAsString() == "work_data_bits") {
        // We found a dereference of work_data_bits() call.
        // Now check if this dereference is conditionally guarded by "from_cancel".
        if (!isGuardedByFromCancel(UO, Context, SM, LangOpts)) {
          // Report the bug: the unguarded read of work->data.
          PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(UO, SM, LangOpts);
          auto *R = new BasicBugReport(*BT,
                                        "Unconditional read of work->data may trigger false-positive data races",
                                        Loc);
          R->addRange(UO->getSourceRange());
          BR.emitReport(std::unique_ptr<BugReport>(R));
        }
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unguarded read of work->data")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

  // No additional callbacks are needed.
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                          BugReporter &BR) const {
  // We only care about the __flush_work function.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (FD->getNameAsString() != "__flush_work")
    return;

  if (const Stmt *Body = FD->getBody()) {
    // Traverse the function body looking for the unguarded read pattern.
    FlushWorkVisitor Visitor(FD->getASTContext(), BR, BT.get());
    Visitor.TraverseStmt(const_cast<Stmt*>(Body));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects unguarded read of work->data in __flush_work that may trigger false-positive data races",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
