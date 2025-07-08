#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/LangOptions.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

using namespace clang;
using namespace ento;

namespace {

// Visitor to traverse the function body and find memcpy calls and 
// assignments to the 'num_trips' member.
class MemcpyAndAssignVisitor : public RecursiveASTVisitor<MemcpyAndAssignVisitor> {
public:
  MemcpyAndAssignVisitor(const ASTContext &Ctx)
      : Ctx(Ctx), SM(Ctx.getSourceManager()),
        MemcpyFound(false), AssignFound(false) {}

  // If a memcpy call is found, record its location.
  bool VisitCallExpr(CallExpr *CE) {
    // Check if the call is to a function named "memcpy".
    if (const FunctionDecl *Callee = CE->getDirectCallee()) {
      if (Callee->getNameAsString() == "memcpy") {
        SourceLocation Loc = CE->getExprLoc();
        // Record the earliest memcpy location.
        if (!MemcpyFound || SM.isBeforeInTranslationUnit(Loc, MemcpyLoc)) {
          MemcpyLoc = Loc;
          MemcpyFound = true;
        }
      }
    }
    return true;
  }

  // Visit any binary operator, and check for assignment to the 'num_trips' field.
  bool VisitBinaryOperator(BinaryOperator *BO) {
    // Check if this is an assignment operator.
    if (BO->getOpcode() == BO_Assign) {
      Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      if (MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
        // Check if the member name is "num_trips".
        if (const ValueDecl *VD = ME->getMemberDecl()) {
          if (VD->getNameAsString() == "num_trips") {
            SourceLocation Loc = BO->getExprLoc();
            if (!AssignFound || SM.isBeforeInTranslationUnit(Loc, AssignLoc)) {
              AssignLoc = Loc;
              AssignFound = true;
            }
          }
        }
      }
    }
    return true;
  }

  // Accessors to check if we found the statements and to get their locations.
  bool hasMemcpy() const { return MemcpyFound; }
  bool hasAssign() const { return AssignFound; }
  SourceLocation getMemcpyLoc() const { return MemcpyLoc; }
  SourceLocation getAssignLoc() const { return AssignLoc; }

private:
  const ASTContext &Ctx;
  const SourceManager &SM;
  SourceLocation MemcpyLoc;
  SourceLocation AssignLoc;
  bool MemcpyFound;
  bool AssignFound;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer Size Misordered",
                                        "Misordered assignments")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                        AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // We only care about function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // Check that this is the target function.
  if (FD->getNameAsString() != "thermal_zone_device_register_with_trips")
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Traverse the function body to find memcpy() calls and assignments to num_trips.
  MemcpyAndAssignVisitor Visitor(FD->getASTContext());
  Visitor.TraverseStmt(const_cast<Stmt*>(Body));

  // To trigger the bug, we need a memcpy call and an assignment to num_trips,
  // and the memcpy must occur before the assignment.
  if (Visitor.hasMemcpy() && Visitor.hasAssign()) {
    const ASTContext &Ctx = FD->getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    if (SM.isBeforeInTranslationUnit(Visitor.getMemcpyLoc(), Visitor.getAssignLoc())) {
      // Report the bug: the buffer is used in memcpy() before its size is assigned.
      SmallString<100> Buf;
      llvm::raw_svector_ostream OS(Buf);
      OS << "Buffer size assigned after memcpy";

      // Create a Basic bug report anchored at the location of the memcpy call.
      PathDiagnosticLocation BugLoc =
          PathDiagnosticLocation::createBegin(Visitor.getMemcpyLoc(), SM, &Ctx.getLangOpts());
      BugReport *R = new BasicBugReport(*BT, OS.str(), BugLoc);
      R->addRange(CharSourceRange::getTokenRange(Visitor.getMemcpyLoc()).getAsRange());
      BR.emitReport(std::unique_ptr<BugReport>(R));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects misordering: assigning buffer size after memcpy() is called",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
