```cpp
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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Attr.h"
#include "clang/Analysis/PathDiagnostic.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track uninitialized auto-cleanup pointer variables by VarDecl*.
REGISTER_SET_WITH_PROGRAMSTATE(UninitCleanupSet, const VarDecl *)
REGISTER_SET_WITH_PROGRAMSTATE(ReportedSet, const VarDecl *)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PostCall,
        check::PreStmt<ReturnStmt>,
        check::EndFunction> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Auto-cleanup pointer freed uninitialized", "Memory Management")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndFunction(CheckerContext &C) const;

private:
  // Helpers
  static bool isLocalAutoPtrWithCleanup(const VarDecl *VD);
  static bool cleanupIsFreeLike(const CleanupAttr *CA);
  static const FunctionDecl *currentFunctionDecl(CheckerContext &C);

  void markInitializedIfTracked(const VarDecl *VD, CheckerContext &C) const;
  void handleOutParamInitialization(const Expr *ArgE, CheckerContext &C) const;
  void reportUninitializedIfAny(CheckerContext &C) const;
};

bool SAGenTestChecker::cleanupIsFreeLike(const CleanupAttr *CA) {
  if (!CA)
    return false;
  if (const FunctionDecl *FD = CA->getFunctionDecl()) {
    StringRef Name = FD->getName();
    if (Name.empty())
      return true; // be conservative if not resolvable
    // Common free-like functions in the kernel environment
    if (Name.equals("kfree") || Name.equals("kvfree") || Name.equals("vfree"))
      return true;
    // Case-insensitive substring check for "free".
    std::string Lower = std::string(Name.lower());
    if (Lower.find("free") != std::string::npos)
      return true;
    return false;
  }
  // If we cannot resolve the function, be conservative and consider it free-like.
  return true;
}

bool SAGenTestChecker::isLocalAutoPtrWithCleanup(const VarDecl *VD) {
  if (!VD)
    return false;
  if (!VD->hasLocalStorage() || VD->isStaticLocal())
    return false;
  QualType QT = VD->getType();
  if (QT.isNull() || !QT->isPointerType())
    return false;
  const CleanupAttr *CA = VD->getAttr<CleanupAttr>();
  if (!CA)
    return false;
  // We only care about cleanup handlers that are likely to free a pointer.
  if (!cleanupIsFreeLike(CA))
    return false;
  return true;
}

const FunctionDecl *SAGenTestChecker::currentFunctionDecl(CheckerContext &C) {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return nullptr;
  return dyn_cast<FunctionDecl>(LCtx->getDecl());
}

void SAGenTestChecker::markInitializedIfTracked(const VarDecl *VD, CheckerContext &C) const {
  if (!VD)
    return;
  ProgramStateRef State = C.getState();
  if (State->contains<UninitCleanupSet>(VD)) {
    State = State->remove<UninitCleanupSet>(VD);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!isLocalAutoPtrWithCleanup(VD))
      continue;

    // If it has an initializer, it's already initialized (safe).
    if (VD->hasInit())
      continue;

    if (!State->contains<UninitCleanupSet>(VD)) {
      State = State->add<UninitCleanupSet>(VD);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  if (const auto *VR = dyn_cast<VarRegion>(MR)) {
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      return;
    // Any assignment to the variable counts as "initialized".
    markInitializedIfTracked(VD, C);
  }
}

void SAGenTestChecker::handleOutParamInitialization(const Expr *ArgE, CheckerContext &C) const {
  if (!ArgE)
    return;

  ArgE = ArgE->IgnoreParenCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(ArgE)) {
    if (UO->getOpcode() == UO_AddrOf) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          // If this variable is tracked, consider it initialized by this call.
          markInitializedIfTracked(VD, C);
          return;
        }
      }
    }
  }

  // Fallback via region: passing &var results in a region value.
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(ArgE, C.getLocationContext());
  if (const MemRegion *MR = SV.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *VR = dyn_cast<VarRegion>(MR)) {
      const VarDecl *VD = VR->getDecl();
      if (VD)
        markInitializedIfTracked(VD, C);
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Heuristic: if any argument is &var and var is tracked, treat it as initialized post-call.
  for (unsigned i = 0, n = Call.getNumArgs(); i < n; ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    handleOutParamInitialization(ArgE, C);
  }
}

void SAGenTestChecker::reportUninitializedIfAny(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!State)
    return;

  const FunctionDecl *CurFD = currentFunctionDecl(C);
  if (!CurFD)
    return;

  auto USet = State->get<UninitCleanupSet>();
  if (USet.isEmpty())
    return;

  for (auto It = USet.begin(); It != USet.end(); ++It) {
    const VarDecl *VD = *It;
    if (!VD)
      continue;

    // Only report variables that belong to the current function.
    const auto *OwnerFD = dyn_cast<FunctionDecl>(VD->getDeclContext());
    if (OwnerFD != CurFD)
      continue;

    if (State->contains<ReportedSet>(VD))
      continue;

    ProgramStateRef NewState = State->add<ReportedSet>(VD);
    ExplodedNode *N = C.generateNonFatalErrorNode(NewState);
    if (!N)
      continue;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "auto-cleanup pointer may be freed uninitialized; initialize to NULL", N);
    R->addRange(VD->getSourceRange());
    PathDiagnosticLocation L = PathDiagnosticLocation::createBegin(VD, C.getASTContext().getSourceManager());
    R->addNote("Declare with '= NULL' to ensure cleanup handler is safe", L, N);
    C.emitReport(std::move(R));

    // Update local State to include the 'reported' mark for subsequent iterations.
    State = NewState;
  }
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  // On any return path, if a tracked variable remains uninitialized, report.
  reportUninitializedIfAny(C);
}

void SAGenTestChecker::checkEndFunction(CheckerContext &C) const {
  // At end of function, report if any tracked variable remains uninitialized.
  reportUninitializedIfAny(C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects auto-cleanup pointers that may be freed uninitialized; suggest initializing to NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
