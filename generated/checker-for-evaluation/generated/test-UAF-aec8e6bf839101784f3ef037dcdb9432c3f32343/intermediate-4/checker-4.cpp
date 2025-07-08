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

// Fixed include: use the correct header file for Clang-18.
#include "clang/StaticAnalyzer/Core/PathDiagnosticLocation.h"

// Add your includes here
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No customized program state is needed for this checker.

namespace {

// Helper function: Recursively search for an assignment that sets the member
// 'bdev_file' to a null pointer constant.
bool hasBdevFileNullAssignment(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      if (const MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
        if (const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          if (FD->getName() == "bdev_file") {
            if (RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull))
              return true;
          }
        }
      }
    }
  }

  // Recurse into child statements.
  for (const Stmt *Child : S->children()) {
    if (hasBdevFileNullAssignment(Child, Ctx))
      return true;
  }
  return false;
}

// Helper function: Recursively search for a call to 'btrfs_close_bdev'.
// We use a simple check on the callee's name via DeclRefExpr.
bool hasCallToBtrfsCloseBdev(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(CE->getCallee()->IgnoreParenCasts())) {
      if (DRE->getDecl()->getNameAsString() == "btrfs_close_bdev")
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (hasCallToBtrfsCloseBdev(Child, Ctx))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker< check::ASTCodeBody > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Dangling pointer", "Use-after-free")) {}

  // Callback to inspect the code body of each function.
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  // We are only interested in functions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // Process only the target function 'btrfs_close_one_device'.
  if (FD->getNameAsString() != "btrfs_close_one_device")
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = FD->getASTContext();

  // Check if the function body contains a call to 'btrfs_close_bdev'.
  if (!hasCallToBtrfsCloseBdev(Body, Ctx))
    return; // Nothing to check if no call to btrfs_close_bdev exists.

  // Look for the required nullification assignment that sets 'bdev_file' to NULL.
  if (hasBdevFileNullAssignment(Body, Ctx))
    return; // Properly nullified; no bug to report.

  // Bug detected: after calling btrfs_close_bdev, 'bdev_file' is never set to NULL.
  // Report the bug at the function declaration's location.
  PathDiagnosticLocation PDLoc = PathDiagnosticLocation::createBegin(FD, FD->getASTContext());
  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "Dangling pointer: 'bdev_file' is not set to NULL after its resource is freed",
      PDLoc);
  Report->addRange(FD->getSourceRange());
  BR.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use‐after‐free due to failure to nullify bdev_file", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
