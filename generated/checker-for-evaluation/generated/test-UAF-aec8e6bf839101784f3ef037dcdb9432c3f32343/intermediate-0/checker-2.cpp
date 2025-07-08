#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;

namespace {

// Visitor to traverse the body of btrfs_close_one_device() and check for proper reset
class CloseOneDeviceVisitor : public RecursiveASTVisitor<CloseOneDeviceVisitor> {
  ASTContext *Context;
public:
  // These flags record whether the required calls/assignments are found
  bool FoundCloseBdevCall;
  bool FoundBdevFileReset;

  CloseOneDeviceVisitor(ASTContext *C)
      : Context(C), FoundCloseBdevCall(false), FoundBdevFileReset(false) {}

  // Visit call expressions: look for a call to btrfs_close_bdev(...)
  bool VisitCallExpr(CallExpr *CE) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getNameAsString() == "btrfs_close_bdev")
        FoundCloseBdevCall = true;
    }
    return true;
  }

  // Visit binary operators: look for assignment to the bdev_file field with a NULL RHS.
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO->isAssignmentOp())
      return true;

    Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    if (MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
      // Check if the member name is "bdev_file"
      if (ME->getMemberNameInfo().getAsString() == "bdev_file") {
        // Check if the right-hand side is a null constant.
        Expr *RHS = BO->getRHS()->IgnoreParenCasts();
        if (RHS->isNullPointerConstant(*Context, Expr::NPC_ValueDependentIsNull))
          FoundBdevFileReset = true;
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Dangling Pointer", "Resource Management")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // Filter for function definitions
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // Only check the function "btrfs_close_one_device"
  if (FD->getNameAsString() != "btrfs_close_one_device")
    return;

  // Ensure the function has a body.
  const Stmt *FuncBody = FD->getBody();
  if (!FuncBody)
    return;

  // Traverse the function body to locate:
  // 1. A call to btrfs_close_bdev()
  // 2. An assignment setting device->bdev_file to NULL.
  CloseOneDeviceVisitor Visitor(&FD->getASTContext());
  Visitor.TraverseStmt(const_cast<Stmt*>(FuncBody));

  // We report the bug if btrfs_close_bdev was called and we did NOT see
  // an assignment resetting the bdev_file field to NULL.
  if (Visitor.FoundCloseBdevCall && !Visitor.FoundBdevFileReset) {
    // Report at the beginning of the function body for clarity.
    PathDiagnosticLocation Loc =
        PathDiagnosticLocation::createBegin(FD->getBody(), BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(*BT,
      "Dangling pointer: bdev_file is not reset to NULL after btrfs_close_bdev frees the resource", Loc);
    Report->addRange(FD->getSourceRange());
    BR.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects failure to clear bdev_file (dangling pointer) after resource free", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
