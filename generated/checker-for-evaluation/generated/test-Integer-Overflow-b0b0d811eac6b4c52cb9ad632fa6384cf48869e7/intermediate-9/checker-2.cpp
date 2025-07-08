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
#include "clang/AST/Expr.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
// Replaced header file for PathDiagnosticLocation with the new location in Clang-18.
#include "clang/StaticAnalyzer/Core/PathDiagnosticConsumers.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper visitor to traverse the function's AST and detect multiplication expressions.
class MultiplicationVisitor : public RecursiveASTVisitor<MultiplicationVisitor> {
  BugReporter &BR;
  const BugType *BT;
  ASTContext *Context;
  const Decl *D; // The surrounding declaration (e.g., FunctionDecl)

public:
  MultiplicationVisitor(BugReporter &br, const BugType *bt, ASTContext *ctx, const Decl *d)
      : BR(br), BT(bt), Context(ctx), D(d) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    // Only consider multiplication operators.
    if (BO->getOpcode() != BO_Mul)
      return true;

    // Retrieve the types of the left and right operands.
    QualType LHSTy = BO->getLHS()->getType();
    QualType RHSTy = BO->getRHS()->getType();

    // Only consider integer types.
    if (!LHSTy->isIntegerType() || !RHSTy->isIntegerType())
      return true;

    // Compare the canonical types. If they differ, the operands have different integer types.
    if (LHSTy.getCanonicalType() == RHSTy.getCanonicalType())
      return true;

    // Report the bug: multiplying integer values of different types may lead to overflow.
    SourceRange MulRange = BO->getSourceRange();
    // Create a valid location for bug reporting.
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(BO, *Context, BR.getSourceManager());
    auto report = std::make_unique<BasicBugReport>(
        *BT,
        "Multiplication of variables with different integer types may cause integer overflow.",
        Loc);
    report->addRange(MulRange);
    BR.emitReport(std::move(report));

    return true;
  }
};

// Checker that uses the ASTCodeBody callback.
class SAGenTestChecker : public Checker<check::ASTCodeBody> { 
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Integer Multiplication Type Mismatch")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // Only process function declarations that have a body.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &Ctx = FD->getASTContext();
  Stmt *Body = FD->getBody();
  MultiplicationVisitor Visitor(BR, BT.get(), &Ctx, D);
  Visitor.TraverseStmt(Body);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects multiplication of variables with different integer types potentially causing integer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
