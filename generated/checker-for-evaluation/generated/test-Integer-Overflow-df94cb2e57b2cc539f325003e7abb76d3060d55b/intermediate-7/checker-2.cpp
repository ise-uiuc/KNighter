#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
// Removed include "clang/StaticAnalyzer/Checkers/Checkers.h" because it does not exist in Clang-18
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;

namespace {

/// Helper class to recursively visit a function body looking for
/// declarations of variables or parameters with names containing "sector"
/// (case-insensitive) that are declared with an insufficient 32-bit type.
class SectorVarVisitor : public RecursiveASTVisitor<SectorVarVisitor> {
  BugReporter &BR;
  const CheckerBase *Checker;
public:
  SectorVarVisitor(BugReporter &BR, const CheckerBase *Checker)
    : BR(BR), Checker(Checker) {}

  // Visit local variable declarations.
  bool VisitVarDecl(VarDecl *VD) {
    if (!VD->getIdentifier())
      return true;
    std::string VarName = VD->getNameAsString();
    // Convert to lower-case.
    for (auto &c : VarName)
      c = tolower(c);
    // Check if the variable name contains "sector"
    if (VarName.find("sector") == std::string::npos)
      return true;

    QualType QT = VD->getType().getCanonicalType();
    // If the type is an unsigned int (typically 32-bit) then warn.
    if (const BuiltinType *BT = dyn_cast<BuiltinType>(QT.getTypePtr())) {
      // Check for "unsigned int" exactly.
      if (BT->getKind() == BuiltinType::UInt) {
        // Report a warning.
        BugType *BTy = new BugType(Checker, "Disk sector count variable width",
                                   "Integer Overflow");
        SmallString<128> buf;
        llvm::raw_svector_ostream os(buf);
        os << "Variable '" << VD->getNameAsString()
           << "' has insufficient width (use u64 instead of unsigned int)";
        PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(VD, BR.getSourceManager());
        auto Report = std::make_unique<BasicBugReport>(*BTy, os.str(), DLoc);
        Report->addRange(VD->getSourceRange());
        BR.emitReport(std::move(Report));
      }
    }
    return true;
  }

  // Also visit parameter declarations.
  bool VisitParmVarDecl(ParmVarDecl *PVD) {
    if (!PVD->getIdentifier())
      return true;
    std::string ParamName = PVD->getNameAsString();
    for (auto &c : ParamName)
      c = tolower(c);
    if (ParamName.find("sector") == std::string::npos)
      return true;

    QualType QT = PVD->getType().getCanonicalType();
    if (const BuiltinType *BT = dyn_cast<BuiltinType>(QT.getTypePtr())) {
      if (BT->getKind() == BuiltinType::UInt) {
        BugType *BTy = new BugType(Checker, "Disk sector count parameter width",
                                   "Integer Overflow");
        SmallString<128> buf;
        llvm::raw_svector_ostream os(buf);
        os << "Parameter '" << PVD->getNameAsString()
           << "' has insufficient width (use u64 instead of unsigned int)";
        PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(PVD, BR.getSourceManager());
        auto Report = std::make_unique<BasicBugReport>(*BTy, os.str(), DLoc);
        Report->addRange(PVD->getSourceRange());
        BR.emitReport(std::move(Report));
      }
    }
    return true;
  }
};

/// Our checker class. We implement two callbacks:
/// 1. checkASTCodeBody to examine function bodies (and indirectly, declarations)
///    for variables whose type is unsigned int but whose names imply disk sector counts.
/// 2. checkPostCall to intercept calls to logging functions (like bch2_trans_inconsistent)
///    and analyze the format string for mismatched specifiers.
class SAGenTestChecker : public Checker<check::ASTCodeBody, check::PostCall> {
  mutable std::unique_ptr<BugType> DeclBugTy;
  mutable std::unique_ptr<BugType> FormatBugTy;
public:
  SAGenTestChecker() {
    DeclBugTy.reset(new BugType(this, "Disk sector count variable width",
                                "Integer Overflow"));
    FormatBugTy.reset(new BugType(this, "Mismatched format specifier for disk sectors",
                                  "Integer Overflow"));
  }

  // This callback inspects function bodies for variable/parameter declarations.
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    // Only inspect function/method definitions.
    if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
      if (FD->hasBody()) {
        SectorVarVisitor Visitor(BR, this);
        Visitor.TraverseStmt(FD->getBody());
      }
    }
  }

  // This callback inspects calls for logging functions with potential format
  // mismatches.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    // Use the utility function ExprHasName for accurate function identification.
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;
    if (!ExprHasName(OriginExpr, "bch2_trans_inconsistent", C))
      return;

    // We assume that one of the arguments is a format string.
    // In the buggy code, the format string contains "%u" (a 32-bit specifier) instead of "%llu".
    // We'll check each argument that is a string literal for the improper specifier.
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      const Expr *ArgExpr = Call.getArgExpr(i);
      if (!ArgExpr)
        continue;
      ArgExpr = ArgExpr->IgnoreImplicit();
      if (const StringLiteral *SL = dyn_cast<StringLiteral>(ArgExpr)) {
        StringRef FormatStr = SL->getString();
        // Look for "%u" that is not preceded by an 'l' (as in "%llu").
        // A simple heuristic check: if "%u" is found.
        if (FormatStr.contains("%u") && !FormatStr.contains("%llu")) {
          // Create a bug report.
          ExplodedNode *N = C.generateNonFatalErrorNode();
          if (!N)
            return;
          auto Report = std::make_unique<PathSensitiveBugReport>(
              *FormatBugTy, "Integer overflow risk: mismatched format specifier for disk sectors (use %llu)", N);
          Report->addRange(ArgExpr->getSourceRange());
          C.emitReport(std::move(Report));
          // Report once per call.
          return;
        }
      }
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Checks for use of insufficient integer width for disk sector counts "
      "and mismatched format specifiers in logging", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
