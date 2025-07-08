#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;

// No custom program state maps are needed for this checker.

namespace {

/// Visitor class to traverse function bodies and detect multiplication (BO_Mul)
/// between integer operands of different types.
class MulVisitor : public RecursiveASTVisitor<MulVisitor> {
  BugReporter &BR;
  const BugType *BT;
  ASTContext &Context;

public:
  MulVisitor(BugReporter &br, const BugType *bt, ASTContext &ctx)
      : BR(br), BT(bt), Context(ctx) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    // Only interested in multiplication operators.
    if (BO->getOpcode() != BO_Mul)
      return true;

    // Get types of left and right operands.
    QualType LhsType = BO->getLHS()->getType();
    QualType RhsType = BO->getRHS()->getType();

    // Only process if both operands are integer types.
    if (!LhsType->isIntegerType() || !RhsType->isIntegerType())
      return true;

    // Get bit widths for the two operands.
    // Note: getTypeInfo returns a TypeInfo that contains the width.
    const uint64_t LhsWidth = Context.getTypeInfo(LhsType).Width;
    const uint64_t RhsWidth = Context.getTypeInfo(RhsType).Width;
    if (LhsWidth == 0 || RhsWidth == 0)
      return true;

    // Get type string representations.
    std::string LhsStr = LhsType.getAsString();
    std::string RhsStr = RhsType.getAsString();

    bool isDifferentBitWidth = (LhsWidth != RhsWidth);
    bool involvesDmaAddr = (LhsStr.find("dma_addr_t") != std::string::npos ||
                              RhsStr.find("dma_addr_t") != std::string::npos);
    bool isDifferentTypeString = (LhsStr != RhsStr);

    // If the operands are of different bit widths or if one operand is dma_addr_t
    // and the other operand's type is different, then this multiplication may
    // lead to unintentional overflow.
    if (isDifferentBitWidth || (involvesDmaAddr && isDifferentTypeString)) {
      // Create a bug report location.
      PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
          BO, Context.getSourceManager());

      SmallString<100> sb;
      llvm::raw_svector_ostream os(sb);
      os << "Potential integer overflow: multiplication between operands of "
            "different types (\""
         << LhsStr << "\" * \"" << RhsStr << "\") may lead to unintended overflow";

      // Report the bug using BasicBugReport.
      auto Report = std::make_unique<BasicBugReport>(*BT, os.str(), Loc);
      Report->addRange(BO->getSourceRange());
      BR.emitReport(std::move(Report));
    }

    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Integer Multiplication Overflow",
                                        "Integer Arithmetic")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  // Only analyze function or method definitions.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  // Retrieve the function body.
  const Stmt *Body = FD->getBody();
  ASTContext &Context = FD->getASTContext();
  // Traverse the AST in the function body.
  MulVisitor Visitor(BR, BT.get(), Context);
  Visitor.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects potential integer overflows when multiplying variables of different integer types",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
