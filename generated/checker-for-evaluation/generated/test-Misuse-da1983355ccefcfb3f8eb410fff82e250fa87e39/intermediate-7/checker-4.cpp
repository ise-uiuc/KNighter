#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Checker.h"  // Updated include path.
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class TripOrderVisitor : public RecursiveASTVisitor<TripOrderVisitor> {
public:
  TripOrderVisitor(ASTContext &Ctx) : Context(Ctx),
    MemcpyLoc(), NumTripsAssignLoc() {}

  bool VisitCallExpr(CallExpr *CE) {
    // Look for memcpy call.
    const Expr *Origin = CE->getCallee()->IgnoreImplicit();
    if (!Origin)
      return true;
    // Use ExprHasName utility to check if function call is memcpy.
    if (ExprHasName(Origin, "memcpy", CheckerContext(Context))) {
      // Record the source location if not already set.
      if (MemcpyLoc.isInvalid())
        MemcpyLoc = CE->getBeginLoc();
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    // Check for assignment operators.
    if (!BO->isAssignmentOp())
      return true;
    // Check if left-hand side is a MemberExpr.
    if (MemberExpr *ME = dyn_cast<MemberExpr>(BO->getLHS()->IgnoreImplicit())) {
      if (FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
        if (FD->getName() == "num_trips") {
          // Record source location.
          if (NumTripsAssignLoc.isInvalid())
            NumTripsAssignLoc = BO->getBeginLoc();
        }
      }
    }
    return true;
  }

  /// Getters for the found locations.
  SourceLocation getMemcpyLoc() const { return MemcpyLoc; }
  SourceLocation getNumTripsAssignLoc() const { return NumTripsAssignLoc; }

private:
  ASTContext &Context;
  SourceLocation MemcpyLoc;
  SourceLocation NumTripsAssignLoc;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Assignment order bug", "Ordering Issue")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // Only inspect function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;
  
  // Check if this is the target function.
  if (FD->getNameAsString() != "thermal_zone_device_register_with_trips")
    return;
  
  ASTContext &Ctx = FD->getASTContext();
  TripOrderVisitor Visitor(Ctx);
  // Traverse the function body.
  Visitor.TraverseStmt(FD->getBody());
  
  SourceLocation memcpyLoc = Visitor.getMemcpyLoc();
  SourceLocation numTripsAssignLoc = Visitor.getNumTripsAssignLoc();
  
  // If either location is invalid, we don't have enough information.
  if (memcpyLoc.isInvalid() || numTripsAssignLoc.isInvalid())
    return;
  
  const SourceManager &SM = Ctx.getSourceManager();
  // Compare the locations: if memcpy occurs before num_trips assignment,
  // then the bug pattern is detected.
  if (SM.isBeforeInTranslationUnit(memcpyLoc, numTripsAssignLoc)) {
    // Report bug: num_trips assigned after memcpy causing fortify check failure.
    ExplodedNode *N = BR.generateNonFatalErrorNode();
    if (!N)
      return;
    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "num_trips assigned after memcpy causing fortify check failure", N);
    report->addRange(FD->getBody()->getSourceRange());
    BR.emitReport(std::move(report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects if num_trips is assigned after memcpy causing fortify check failure", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
