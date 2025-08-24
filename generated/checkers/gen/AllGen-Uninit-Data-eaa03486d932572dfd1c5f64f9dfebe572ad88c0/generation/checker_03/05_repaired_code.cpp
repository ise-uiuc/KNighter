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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map tracked local integer-like status variables to their initialization state.
// true  -> still uninitialized on current path
// false -> definitely initialized (written) on current path
REGISTER_MAP_WITH_PROGRAMSTATE(StatusInitMap, const MemRegion*, bool)

namespace {

static bool isIntegerLike(QualType T) {
  if (T.isNull())
    return false;
  QualType CT = T.getCanonicalType();
  return CT->isIntegerType() || CT->isEnumeralType();
}

static bool isLocalAutomatic(const VarDecl *VD) {
  if (!VD)
    return false;
  // Local automatic storage (non-static local)
  return VD->hasLocalStorage() && !VD->isStaticLocal();
}

static bool isStatusName(const VarDecl *VD) {
  if (!VD)
    return false;
  IdentifierInfo *II = VD->getIdentifier();
  if (!II)
    return false;
  StringRef N = II->getName();
  return N == "ret" || N == "rc" || N == "err" || N == "error";
}

static const MemRegion *getBaseVarRegion(const MemRegion *R) {
  if (!R) return nullptr;
  return R->getBaseRegion();
}

static bool currentFunctionReturnsIntegerLike(CheckerContext &C) {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return false;
  const Decl *D = LC->getDecl();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;
  QualType RT = FD->getReturnType();
  return isIntegerLike(RT);
}

/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
      check::PostStmt<DeclStmt>,
      check::Bind,
      check::PreStmt<ReturnStmt>
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Returning uninitialized status variable", "Uninitialized Value")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

   private:
      // Track all integer-like locals by default.
      // Set to false to only track names like ret/rc/err/error.
      static constexpr bool TrackAllReturnVars = true;

      void reportUninitializedReturn(const VarDecl *VD, const ReturnStmt *RS, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  // Only meaningful in functions that return integer-like types.
  if (!currentFunctionReturnsIntegerLike(C))
    return;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    // Only track local automatic integer-like variables declared without initializer.
    if (!isLocalAutomatic(VD))
      continue;

    if (!isIntegerLike(VD->getType()))
      continue;

    if (VD->hasInit())
      continue;

    if (!TrackAllReturnVars && !isStatusName(VD))
      continue;

    // Get the variable's memory region.
    auto &MRMgr = SVB.getRegionManager();
    const MemRegion *MR = MRMgr.getVarRegion(VD, LCtx);
    if (!MR)
      continue;

    MR = getBaseVarRegion(MR);
    if (!MR)
      continue;

    // Mark as uninitialized on this path.
    State = State->set<StatusInitMap>(MR, true);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt * /*S*/, CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  MR = getBaseVarRegion(MR);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Tracked = State->get<StatusInitMap>(MR);
  if (!Tracked)
    return;

  // Any write counts as initialization.
  if (*Tracked) {
    State = State->set<StatusInitMap>(MR, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportUninitializedReturn(const VarDecl *VD, const ReturnStmt *RS, CheckerContext &C) const {
  if (!VD || !RS)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg = std::string("Returning uninitialized status variable '") +
                    VD->getName().str() + "'";
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(RS->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;

  // Only warn in functions returning integer-like types.
  if (!currentFunctionReturnsIntegerLike(C))
    return;

  const Expr *RV = RS->getRetValue();
  if (!RV)
    return;

  // We only care when returning a tracked variable directly (possibly with parens/casts).
  const Expr *E = RV->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  // Must be integer-like local automatic we might have tracked.
  if (!isLocalAutomatic(VD) || !isIntegerLike(VD->getType()))
    return;

  // Get the region of the returned variable.
  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  auto &MRMgr = SVB.getRegionManager();
  const MemRegion *MR = MRMgr.getVarRegion(VD, LCtx);
  if (!MR)
    return;

  MR = getBaseVarRegion(MR);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Tracked = State->get<StatusInitMap>(MR);
  if (!Tracked)
    return;

  // If still uninitialized on this path, report.
  if (*Tracked) {
    reportUninitializedReturn(VD, RS, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects returning an uninitialized status variable on some control-flow paths",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
