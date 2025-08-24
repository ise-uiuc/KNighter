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
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<ReturnStmt>> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this, "Uninitialized status variable returned",
                                     "Logic")) {}

  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  bool isStatusVarCandidate(const VarDecl *VD) const;
};

bool SAGenTestChecker::isStatusVarCandidate(const VarDecl *VD) const {
  if (!VD)
    return false;

  // Must be a local (non-static) variable.
  if (!VD->isLocalVarDecl() || VD->isStaticLocal())
    return false;

  QualType Ty = VD->getType();
  if (Ty.isNull())
    return false;

  // Only consider integer-like scalars (or enums).
  if (!(Ty->isIntegerType() || Ty->isEnumeralType()))
    return false;

  // Must have no initializer.
  if (VD->hasInit())
    return false;

  // Heuristic: match common status variable name "ret" to reduce noise.
  if (!VD->getIdentifier())
    return false;
  if (VD->getName() != "ret")
    return false;

  return true;
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  // We only consider direct returns of a single variable, e.g., "return ret;"
  const Expr *E = RetE->IgnoreImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  if (!isStatusVarCandidate(VD))
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  // Query the current value of the variable at the return site.
  SVal SV = State->getSVal(DRE, C.getLocationContext());
  if (!SV.isUndef())
    return;

  // Report: returning an uninitialized local 'ret'.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Returning uninitialized local 'ret'", N);
  R->addRange(RetE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect returning uninitialized local status variable (e.g., 'ret')",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
