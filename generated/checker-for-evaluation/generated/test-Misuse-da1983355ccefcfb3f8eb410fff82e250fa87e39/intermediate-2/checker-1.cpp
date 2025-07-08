#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;  // 'taint' namespace removed as it does not exist in this environment.

// No extra program state is required for this checker.

namespace {

// A helper RecursiveASTVisitor to traverse the function body and record
// the SourceLocations of memcpy calls and num_trips assignments.
class MemCpyNumTripsVisitor : public RecursiveASTVisitor<MemCpyNumTripsVisitor> {
public:
  explicit MemCpyNumTripsVisitor(ASTContext &Ctx)
      : Ctx(Ctx) {}

  // Vector to store source offsets of memcpy calls.
  llvm::SmallVector<unsigned, 4> MemCpyOffsets;
  // Vector to store source offsets of assignments to num_trips.
  llvm::SmallVector<unsigned, 4> NumTripsOffsets;

  // Visit CallExpr to capture memcpy calls.
  bool VisitCallExpr(CallExpr *CE) {
    const Expr *CalleeExpr = CE->getCallee();
    if (!CalleeExpr)
      return true;

    // Use the utility function to get the callee name from source text.
    // We check that the expression contains "memcpy".
    if (ExprHasName(CalleeExpr, "memcpy", Ctx)) {
      // Get file offset for the call.
      SourceLocation Loc = CE->getExprLoc();
      if (Loc.isValid() && Loc.isFileID()) {
        unsigned Offset = Ctx.getSourceManager().getFileOffset(Loc);
        MemCpyOffsets.push_back(Offset);
      }
    }
    return true;
  }

  // Visit BinaryOperator to capture assignments to num_trips.
  bool VisitBinaryOperator(BinaryOperator *BO) {
    // Ensure it is an assignment.
    if (!BO->isAssignmentOp())
      return true;

    Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    if (!LHS)
      return true;

    // Check if LHS is a MemberExpr.
    if (MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
      // Get the member name.
      if (const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
        if (FD->getName() == "num_trips") {
          SourceLocation Loc = BO->getOperatorLoc();
          if (Loc.isValid() && Loc.isFileID()) {
            unsigned Offset = Ctx.getSourceManager().getFileOffset(Loc);
            NumTripsOffsets.push_back(Offset);
          }
        }
      }
    }
    return true;
  }

private:
  ASTContext &Ctx;
};

// The main checker class
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer copy order issue",
                                        "Initialization Order Issue")) {}

  // This callback is invoked for every function that has a body.
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  // Helper function to report bug.
  void reportBug(const Decl *D, BugReporter &BR, const SourceManager &SM,
                 SourceLocation memcpyLoc, SourceLocation assignLoc) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // We are interested only in function declarations.
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
    // Check if the function name is "thermal_zone_device_register_with_trips".
    if (FD->getNameAsString() != "thermal_zone_device_register_with_trips")
      return;

    // Get the function body.
    const Stmt *Body = FD->getBody();
    if (!Body)
      return;

    ASTContext &Ctx = FD->getASTContext();
    MemCpyNumTripsVisitor Visitor(Ctx);
    Visitor.TraverseStmt(const_cast<Stmt*>(Body));

    // If we have both memcpy and num_trips assignments, compare their order.
    if (Visitor.MemCpyOffsets.empty() || Visitor.NumTripsOffsets.empty())
      return;

    // For simplicity, get the earliest memcpy call and earliest num_trips assignment.
    unsigned EarliestMemcpy = Visitor.MemCpyOffsets[0];
    for (unsigned Offset : Visitor.MemCpyOffsets)
      EarliestMemcpy = std::min(EarliestMemcpy, Offset);

    unsigned EarliestAssign = Visitor.NumTripsOffsets[0];
    for (unsigned Offset : Visitor.NumTripsOffsets)
      EarliestAssign = std::min(EarliestAssign, Offset);

    // If memcpy occurs before the num_trips assignment, that's our bug.
    if (EarliestMemcpy < EarliestAssign) {
      const SourceManager &SM = Ctx.getSourceManager();
      // Recover SourceLocations from offsets.
      // For reporting, we pick the first memcpy and first assignment locations.
      SourceLocation memcpyLoc, assignLoc;
      for (unsigned Offset : Visitor.MemCpyOffsets) {
        if (Offset == EarliestMemcpy) {
          // For reporting, we use a dummy location from FD->getLocation().
          memcpyLoc = FD->getLocation();
          break;
        }
      }
      for (unsigned Offset : Visitor.NumTripsOffsets) {
        if (Offset == EarliestAssign) {
          assignLoc = FD->getLocation();
          break;
        }
      }
      reportBug(D, BR, SM, memcpyLoc, assignLoc);
    }
  }
}

void SAGenTestChecker::reportBug(const Decl *D, BugReporter &BR,
                                 const SourceManager &SM,
                                 SourceLocation memcpyLoc,
                                 SourceLocation assignLoc) const {
  // Report bug using a PathSensitiveBugReport with a null error node.
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer copied before num_trips is initialized", nullptr);
  BR.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Checks that memcpy is called after num_trips is initialized in thermal_zone_device_register_with_trips", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
