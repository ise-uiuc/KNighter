#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

//////////////////////////////////////////////////////////////////////////
// This checker detects a bug pattern where disk sector counters are declared
// using a too-narrow (e.g., 32-bit unsigned) integer type. Such counters,
// later used in arithmetic and formatting (e.g. with "%u" in a printf format)
// can overflow when handling 64-bit values and cause incorrect calculations.
// This checker inspects variable declarations and call expressions within
// function bodies to flag potential issues.
//////////////////////////////////////////////////////////////////////////

// Recursive AST visitor to search for problematic declarations and call formats.
class UnsignedDiskSectorVisitor : public RecursiveASTVisitor<UnsignedDiskSectorVisitor> {
  BugReporter &BR;
  ASTContext &Ctx;
  const BugType &BT;
public:
  UnsignedDiskSectorVisitor(BugReporter &BR, ASTContext &Ctx, const BugType &BT)
      : BR(BR), Ctx(Ctx), BT(BT) {}

  // Visit variable declarations.
  bool VisitVarDecl(VarDecl *VD) {
    QualType QT = VD->getType();
    // Check if this is an unsigned integer type with less than 64 bits.
    if (QT->isUnsignedIntegerType() && Ctx.getTypeSize(QT) < 64) {
      if (Expr *Init = VD->getInit()) {
        // Look in the initializer for a member expression that accesses "sectors".
        bool FoundSectors = false;
        class MemberExprFinder : public RecursiveASTVisitor<MemberExprFinder> {
        public:
          bool Found = false;
          bool VisitMemberExpr(MemberExpr *ME) {
            if (ME->getMemberDecl() &&
                ME->getMemberDecl()->getNameAsString() == "sectors")
              Found = true;
            return true;
          }
        } Finder;
        Finder.TraverseStmt(Init);
        if (Finder.Found) {
          // Report the bug on the declaration.
          PathDiagnosticLocation Loc =
              PathDiagnosticLocation::createBegin(VD->getLocation(), BR.getSourceManager(), Ctx.getLangOpts());
          // Create a BasicBugReport with the appropriate description.
          BasicBugReport *report =
              new BasicBugReport(BT,
                                 "Possible integer overflow: narrow integer type for disk sector counter. "
                                 "The disk sector counter is declared using an unsigned integer type which might be too narrow for 64-bit disk sectors.",
                                 Loc);
          report->addRange(VD->getSourceRange());
          BR.emitReport(report);
        }
      }
    }
    return true;
  }

  // Visit call expressions.
  bool VisitCallExpr(CallExpr *CE) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      // Identify calls to bch2_trans_inconsistent.
      if (FD->getNameAsString() == "bch2_trans_inconsistent") {
        // Expect the format string to be the second argument.
        if (CE->getNumArgs() > 1) {
          if (const StringLiteral *SL =
                  dyn_cast<StringLiteral>(CE->getArg(1)->IgnoreImpCasts())) {
            StringRef Str = SL->getString();
            // If the format string uses "%u" (narrow) and does not use "%llu" (64-bit), then warn.
            if (Str.contains("%u") && !Str.contains("%llu")) {
              PathDiagnosticLocation Loc =
                  PathDiagnosticLocation::createBegin(SL->getBeginLoc(), BR.getSourceManager(), Ctx.getLangOpts());
              BasicBugReport *report =
                  new BasicBugReport(BT,
                                     "Format string mismatch: expected '%llu' for disk sector counter. "
                                     "The format string used for printing the disk sector counter is '%u', but the counter should be 64-bit; consider using '%llu'.",
                                     Loc);
              report->addRange(SL->getSourceRange());
              BR.emitReport(report);
            }
          }
        }
      }
    }
    return true;
  }
};

//////////////////////////////////////////////////////////////////////////
// Checker Implementation
//////////////////////////////////////////////////////////////////////////

namespace {

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() {
    BT.reset(new BugType(this, "Narrow Disk Sector Counter", "Integer Overflow"));
  }

  // Traverse the function body to search for declarations and call expressions
  // related to disk sector counters.
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    // We are only interested in function definitions.
    if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
      if (!FD->hasBody())
        return;
      ASTContext &Ctx = FD->getASTContext();
      UnsignedDiskSectorVisitor Visitor(BR, Ctx, *BT);
      Visitor.TraverseStmt(FD->getBody());
    }
  }
};

} // end anonymous namespace

//////////////////////////////////////////////////////////////////////////
// Checker Registration
//////////////////////////////////////////////////////////////////////////

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of a narrow integer type for disk sector counters that may lead to integer overflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
