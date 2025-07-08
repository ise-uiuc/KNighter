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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include <string>

// Include appropriate header for BasicBugReport.
#include "clang/StaticAnalyzer/Core/BugReporter/BugReport.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

//---------------------------------------------------------------------
// ForLoopBodyVisitor: Traverse the body of a ForStmt looking for
//   1. An array subscript expression that accesses a member named "DcfClocks".
//   2. An if-statement whose condition text contains "VG_NUM_DCFCLK_DPM_LEVELS".
//---------------------------------------------------------------------
class ForLoopBodyVisitor : public RecursiveASTVisitor<ForLoopBodyVisitor> {
public:
  bool foundDcfClocks = false;
  bool safeGuardFound = false;
  const SourceManager &SM;
  LangOptions LangOpts;
  
  ForLoopBodyVisitor(const SourceManager &SM)
    : SM(SM) {
    // Set language options for C.
    LangOpts.CPlusPlus = false;
  }
  
  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    // Get the base of the subscript expression.
    Expr *BaseExpr = ASE->getBase()->IgnoreParenCasts();
    if (auto *ME = dyn_cast<MemberExpr>(BaseExpr)) {
      std::string memberName = ME->getMemberNameInfo().getAsString();
      if (memberName == "DcfClocks")
        foundDcfClocks = true;
    }
    return true;
  }
  
  bool VisitIfStmt(IfStmt *IfS) {
    if (Expr *Cond = IfS->getCond()) {
      // Get the source text for the condition.
      SourceRange SR = Cond->getSourceRange();
      StringRef condText = Lexer::getSourceText(CharSourceRange::getTokenRange(SR),
                                                SM, LangOpts);
      if (condText.contains("VG_NUM_DCFCLK_DPM_LEVELS"))
        safeGuardFound = true;
    }
    return true;
  }
};

//---------------------------------------------------------------------
// DcfVisitor: Traverse the AST of a function to detect for-loops in
// "find_dcfclk_for_voltage" that iterate using VG_NUM_SOC_VOLTAGE_LEVELS,
// then check for non-guarded accesses to the DcfClocks array.
//---------------------------------------------------------------------
class DcfVisitor : public RecursiveASTVisitor<DcfVisitor> {
  BugType *BT;
  BugReporter *BR;
  const SourceManager *SM;
  LangOptions LangOpts;
public:
  DcfVisitor(BugType *BT, BugReporter *BR, const SourceManager *SM)
    : BT(BT), BR(BR), SM(SM) {
      LangOpts.CPlusPlus = false;
  }
  
  bool VisitForStmt(ForStmt *FS) {
    // Check that the for-loop has a condition.
    if (!FS->getCond())
      return true;
    SourceRange condRange = FS->getCond()->getSourceRange();
    StringRef condText = Lexer::getSourceText(CharSourceRange::getTokenRange(condRange),
                                              *SM, LangOpts);
    // We are interested only in loops that use VG_NUM_SOC_VOLTAGE_LEVELS.
    if (!condText.contains("VG_NUM_SOC_VOLTAGE_LEVELS"))
      return true;
    
    // Use the ForLoopBodyVisitor to traverse the loop body.
    ForLoopBodyVisitor bodyVisitor(*SM);
    bodyVisitor.TraverseStmt(FS->getBody());
    
    // If the loop contains an access to "DcfClocks" and no safe guard condition,
    // then we report a potential buffer overflow risk.
    if (bodyVisitor.foundDcfClocks && !bodyVisitor.safeGuardFound) {
      // Report the bug at the location of the for-loop.
      PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(FS, *SM, LangOpts);
      auto Report = std::make_unique<BasicBugReport>(
          *BT,
          "Buffer overflow risk: loop index may exceed DcfClocks array size",
          Loc);
      Report->addRange(FS->getSourceRange());
      BR->emitReport(std::move(Report));
    }
    return true;
  }
};

//---------------------------------------------------------------------
// Checker Class
//---------------------------------------------------------------------
class SAGenTestChecker : public Checker<check::ASTCodeBody> { 
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() : BT(new BugType(this, "Out-of-bounds Array Access",
                                        "Buffer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // We are only interested in function definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  
  // Check if this is the target function.
  if (FD->getNameAsString() != "find_dcfclk_for_voltage")
    return;
  
  // Ensure we have a function body.
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;
  
  const SourceManager &SM = Mgr.getSourceManager();
  
  // Traverse the function body to look for for-loops.
  DcfVisitor visitor(BT.get(), &BR, &SM);
  visitor.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential buffer overflow by iterating over a range larger than the allocated array size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
