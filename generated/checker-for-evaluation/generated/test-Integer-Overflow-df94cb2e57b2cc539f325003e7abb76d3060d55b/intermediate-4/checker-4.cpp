#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
// Use Checker.h from the Static Analyzer.
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
// Fix: Updated include path for Clang-18.
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>
#include <string>

using namespace clang;
using namespace ento;

namespace {

// Visitor to traverse function bodies and check local variable declarations.
class SectorVisitor : public RecursiveASTVisitor<SectorVisitor> {
  BugReporter &BR;
  const BugType *BT;
  ASTContext &Ctx;
public:
  SectorVisitor(BugReporter &br, const BugType *bt, ASTContext &ctx)
    : BR(br), BT(bt), Ctx(ctx) {}

  bool VisitVarDecl(VarDecl *VD) {
    if (!VD)
      return true;
    // Check if the variable name contains "sector".
    std::string VarName = VD->getNameAsString();
    if (VarName.find("sector") == std::string::npos)
      return true;

    QualType QT = VD->getType();
    // Only consider integer types.
    if (!QT->isIntegerType())
      return true;

    // Obtain the size of the type in bits.
    uint64_t TypeSize = Ctx.getTypeSize(QT);
    if (TypeSize < 64) {
      SourceLocation Loc = VD->getLocation();
      llvm::SmallString<100> Buf;
      llvm::raw_svector_ostream OS(Buf);
      OS << "Disk sector count declared with a narrow integer type ("
         << TypeSize << " bits)";
      // Create a PathDiagnosticLocation from the source location.
      PathDiagnosticLocation DiagLoc =
          PathDiagnosticLocation::createBegin(Loc, BR.getSourceManager(), Ctx);
      // Create a BasicBugReport using std::make_unique.
      auto report = std::make_unique<BasicBugReport>(*BT, OS.str(), DiagLoc);
      BR.emitReport(std::move(report));
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTDecl, check::ASTBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(new BugType("custom", "Improper integer type for disk sector count")) {}

  // Check function declarations' parameters.
  void checkASTDecl(const FunctionDecl *FD, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    if (!FD)
      return;
    // Iterate through all parameters.
    for (const ParmVarDecl *Param : FD->parameters()) {
      std::string ParamName = Param->getNameAsString();
      if (ParamName.find("sector") == std::string::npos)
        continue;
      QualType QT = Param->getType();
      // Only check integer types.
      if (!QT->isIntegerType())
        continue;
      // Use the ASTContext to get the integer type size in bits.
      uint64_t TypeSize = FD->getASTContext().getTypeSize(QT);
      if (TypeSize < 64) {
        SourceLocation Loc = Param->getLocation();
        llvm::SmallString<100> Buf;
        llvm::raw_svector_ostream OS(Buf);
        OS << "Improper integer type for disk sector count ("
           << TypeSize << " bits)";
        // Create a PathDiagnosticLocation for reporting.
        PathDiagnosticLocation DiagLoc =
            PathDiagnosticLocation::createBegin(Loc,
                                                  FD->getASTContext().getSourceManager(),
                                                  FD->getASTContext());
        // Report using BasicBugReport.
        auto report = std::make_unique<BasicBugReport>(*BT, OS.str(), DiagLoc);
        BR.emitReport(std::move(report));
      }
    }
  }

  // Check variable declarations in function bodies.
  void checkASTBody(const Decl *D, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    if (!D)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    SectorVisitor Visitor(BR, BT.get(), Ctx);
    Visitor.TraverseDecl(const_cast<Decl*>(D));
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Ensures disk sector count variables are declared with a 64-bit integer type",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
