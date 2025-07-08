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
// Removed inclusion of "clang/StaticAnalyzer/Checkers/utility.h" as it triggers old API usage.

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include <string>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Helper visitor to scan the function body for local variables
// that are used for disk sector calculations.
class SectorDeclVisitor : public RecursiveASTVisitor<SectorDeclVisitor> {
  BugReporter &BR;
  ASTContext &Ctx;
  const BugType *BT;
public:
  SectorDeclVisitor(BugReporter &BR, ASTContext &Ctx, const BugType *BT)
    : BR(BR), Ctx(Ctx), BT(BT) {}

  bool VisitVarDecl(const VarDecl *VD) {
    if (!VD->getIdentifier())
      return true;

    // Check for local variable named "disk_res_sectors"
    StringRef varName = VD->getName();
    if (varName == "disk_res_sectors") {
      QualType T = VD->getType();
      if (T->isUnsignedIntegerType()) {
        // Get the width (in bits) of the type.
        unsigned width = Ctx.getTypeSize(T);
        if (width < 64) {
          // Create a diagnostic location based on the beginning of the VarDecl.
          // Use the overload taking a Decl* instead of a SourceLocation.
          PathDiagnosticLocation Loc =
              PathDiagnosticLocation::createBegin(VD, Ctx);
          auto *R = new BasicBugReport(*BT,
              "Potential integer overflow: local variable 'disk_res_sectors' should be a 64-bit type",
              Loc);
          R->addRange(VD->getSourceRange());
          BR.emitReport(std::unique_ptr<BugReport>(R));
        }
      }
    }
    return true;
  }
};

namespace {

class SAGenTestChecker : public Checker<check::ASTDecl> {
  // Lazily-initialized bug type.
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() = default;

  // Callback invoked for every declaration in the AST.
  void checkASTDecl(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    // Lazily initialize the BugType with the new API that takes only name and description.
    if (!BT)
      BT.reset(new BugType("custom.SAGenTestChecker",
                           "Integer Overflow in Disk Sector Calculations"));

    if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
      if (!FD->hasBody())
        return;
      
      std::string funcName = FD->getNameAsString();

      // --- Check target function: bch2_extent_fallocate ---
      // Its parameter "sectors" is used for disk sector calculation.
      if (funcName == "bch2_extent_fallocate") {
        unsigned numParams = FD->getNumParams();
        for (unsigned i = 0; i < numParams; ++i) {
          const ParmVarDecl *PVD = FD->getParamDecl(i);
          // Look for a parameter exactly named "sectors".
          if (PVD->getName() == "sectors") {
            QualType paramType = PVD->getType();
            if (paramType->isUnsignedIntegerType()) {
              // Check if the bit-width is less than 64.
              unsigned width = FD->getASTContext().getTypeSize(paramType);
              if (width < 64) {
                // Use the overload taking a Decl*.
                PathDiagnosticLocation Loc =
                    PathDiagnosticLocation::createBegin(PVD, FD->getASTContext());
                auto *R = new BasicBugReport(*BT,
                    "Potential integer overflow: parameter 'sectors' should be a 64-bit type",
                    Loc);
                R->addRange(PVD->getSourceRange());
                BR.emitReport(std::unique_ptr<BugReport>(R));
              }
            }
          }
        }
      }

      // --- Check target function: bch2_trans_fs_usage_apply ---
      // Its local variable "disk_res_sectors" is used for reserve calculations.
      if (funcName == "bch2_trans_fs_usage_apply") {
        SectorDeclVisitor visitor(BR, FD->getASTContext(), BT.get());
        visitor.TraverseStmt(FD->getBody());
      }
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential integer overflows in disk sector calculations due to insufficiently wide integer types",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
