#include "clang/AST/Attr.h"
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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper function to check if a VarDecl has a cleanup attribute indicating auto‐cleanup.
// In this bug pattern we look for declarations with the __free attribute.
static bool hasFreeCleanupAttr(const VarDecl *VD) {
  // Iterate over all attributes to see if one is a cleanup attribute.
  // Typically auto-cleanup variables use the cleanup attribute.
  for (const Attr *A : VD->attrs()) {
    if (isa<CleanupAttr>(A))
      return true;
  }
  return false;
}

class SAGenTestChecker 
  : public Checker< check::PostStmt<DeclStmt> > {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Auto-cleanup pointer not initialized")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  // Iterate through all declarations in the statement.
  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
      
    // We only care about pointer types.
    QualType QT = VD->getType();
    if (!QT->isPointerType())
      continue;
      
    // We are targeting auto-cleanup pointers, which we assume are annotated with a cleanup attribute.
    if (!hasFreeCleanupAttr(VD))
      continue;
      
    // Check whether the variable has an initializer.
    // We expect auto-cleanup pointers to be explicitly initialized to NULL.
    if (VD->hasInit()) {
      // Optionally, you could further check whether the initializer is equivalent to NULL.
      // Here, we will accept any initializer as being an initialization.
      continue;
    }
      
    // Report a bug: pointer with auto-cleanup (i.e. __free) is not initialized.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      continue;
      
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Auto-cleanup pointer not initialized to NULL", N);
    R->addRange(VD->getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects auto-cleanup pointer declarations without an initializer (should be initialized to NULL)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
