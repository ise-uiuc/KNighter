#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

namespace {

// Visitor to walk the function body of bch2_trans_fs_usage_apply
// and check the declaration of "disk_res_sectors".
class DiskResVisitor : public RecursiveASTVisitor<DiskResVisitor> {
  const ASTContext &Ctx;
  BugReporter &BR;
  const BugType *BT;

public:
  DiskResVisitor(const ASTContext &Ctx, BugReporter &BR, const BugType *BT)
      : Ctx(Ctx), BR(BR), BT(BT) {}

  bool VisitVarDecl(VarDecl *VD) {
    if (VD->getNameAsString() == "disk_res_sectors") {
      QualType QT = VD->getType();
      // Get the bit-width of the type.
      unsigned bits = Ctx.getTypeSize(QT);
      if (bits < 64) {
        // Report a warning: the variable uses a small type that may overflow.
        auto Loc = PathDiagnosticLocation::createBegin(
            VD->getLocation(), BR.getSourceManager(), Ctx.getLangOpts());
        auto report = std::make_unique<BasicBugReport>(
            *BT,
            "Potential integer overflow: disk sector count variable uses small type",
            Loc);
        report->addRange(VD->getSourceRange());
        BR.emitReport(std::move(report));
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTDecl> {
public:
  // Added a public member to support legacy registration expectations.
  const char *Name = nullptr;

  // Added a static _register method to support legacy registration.
  static void _register(SAGenTestChecker *checker, CheckerManager &mgr) {
    // No additional registration steps needed.
  }

  mutable std::unique_ptr<BugType> BT;

  SAGenTestChecker()
      // In Clang 18 the BugType constructor expects a pointer to the checker.
      : BT(new BugType(this, "Potential Integer Overflow", "Integer Overflow")) {}

  // Callback to analyze each AST declaration.
  void checkASTDecl(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTDecl(const Decl *D, AnalysisManager &Mgr,
                                    BugReporter &BR) const {
  // We are interested only in function declarations.
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
    if (!FD->hasBody())
      return;

    ASTContext &Ctx = FD->getASTContext();

    // Check function "bch2_trans_fs_usage_apply"
    if (FD->getNameAsString() == "bch2_trans_fs_usage_apply") {
      // Traverse the function body to locate variable declarations.
      DiskResVisitor visitor(Ctx, BR, BT.get());
      visitor.TraverseStmt(FD->getBody());
    }
    // Check function "bch2_extent_fallocate"
    else if (FD->getNameAsString() == "bch2_extent_fallocate") {
      // Iterate through the function's parameters.
      for (unsigned i = 0, e = FD->getNumParams(); i < e; ++i) {
        const ParmVarDecl *PVD = FD->getParamDecl(i);
        if (PVD->getNameAsString() == "sectors") {
          QualType QT = PVD->getType();
          unsigned bits = Ctx.getTypeSize(QT);
          if (bits < 64) {
            // Report a bug: the 'sectors' parameter type is too small.
            auto Loc = PathDiagnosticLocation::createBegin(
                PVD->getLocation(), BR.getSourceManager(), Ctx.getLangOpts());
            auto report = std::make_unique<BasicBugReport>(
                *BT, "Potential integer overflow: sectors parameter type is too small", Loc);
            report->addRange(PVD->getSourceRange());
            BR.emitReport(std::move(report));
          }
        }
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of small integer types for disk sector counts that may overflow", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
