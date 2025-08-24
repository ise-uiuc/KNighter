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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(StatusVarAssignedMap, const MemRegion*, bool)
REGISTER_SET_WITH_PROGRAMSTATE(ReportedSet, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Uninitialized return", "Logic error")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

   private:
      static const FunctionDecl *getEnclosingFunction(const CheckerContext &C);
      static bool functionReturnsInteger(const CheckerContext &C);
      static bool isCandidateStatusVar(const VarDecl *VD, const CheckerContext &C);
      static const MemRegion *getVarRegion(const VarDecl *VD, CheckerContext &C);
      void reportUninitializedReturn(const VarDecl *VD, const MemRegion *R,
                                     const ReturnStmt *RS, CheckerContext &C) const;
};

const FunctionDecl *SAGenTestChecker::getEnclosingFunction(const CheckerContext &C) {
  const Decl *D = C.getLocationContext() ? C.getLocationContext()->getDecl() : nullptr;
  return dyn_cast_or_null<FunctionDecl>(D);
}

bool SAGenTestChecker::functionReturnsInteger(const CheckerContext &C) {
  const FunctionDecl *FD = getEnclosingFunction(C);
  if (!FD)
    return false;
  return FD->getReturnType()->isIntegerType();
}

bool SAGenTestChecker::isCandidateStatusVar(const VarDecl *VD, const CheckerContext &C) {
  if (!VD)
    return false;

  if (!VD->hasLocalStorage())
    return false;
  if (VD->isStaticLocal())
    return false;
  if (!VD->getType()->isIntegerType())
    return false;
  if (VD->hasInit())
    return false;
  if (!functionReturnsInteger(C))
    return false;

  if (const IdentifierInfo *II = VD->getIdentifier()) {
    StringRef Name = II->getName();
    if (Name == "ret" || Name == "rc" || Name == "err")
      return true;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getVarRegion(const VarDecl *VD, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  if (!State || !VD)
    return nullptr;
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return nullptr;
  const MemRegion *MR = State->getRegionManager().getVarRegion(VD, LCtx);
  return MR;
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  ProgramStateRef State = C.getState();
  ProgramStateRef NewState = State;

  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!isCandidateStatusVar(VD, C))
      continue;

    const MemRegion *MR = getVarRegion(VD, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Initialize tracking as "unassigned"/"uninitialized"
    NewState = NewState->set<StatusVarAssignedMap>(MR, false);
  }

  if (NewState != State)
    C.addTransition(NewState);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;
  R = R->getBaseRegion();
  if (!R)
    return;

  const bool *Tracked = State->get<StatusVarAssignedMap>(R);
  if (!Tracked)
    return;

  // Any store to the tracked variable marks it as assigned on this path.
  ProgramStateRef NewState = State->set<StatusVarAssignedMap>(R, true);
  if (NewState != State)
    C.addTransition(NewState);
}

void SAGenTestChecker::reportUninitializedReturn(const VarDecl *VD, const MemRegion *R,
                                                 const ReturnStmt *RS, CheckerContext &C) const {
  if (!BT || !R || !RS)
    return;

  ProgramStateRef State = C.getState();

  // Avoid duplicate reports for the same region on the same path.
  if (State->contains<ReportedSet>(R))
    return;

  ProgramStateRef NewState = State->add<ReportedSet>(R);
  ExplodedNode *N = C.generateNonFatalErrorNode(NewState);
  if (!N)
    return;

  std::string VarName = VD ? VD->getName().str() : std::string("variable");
  std::string Msg = "returning uninitialized local '" + VarName + "'";

  auto Rpt = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  Rpt->addRange(RS->getSourceRange());
  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;
  if (!functionReturnsInteger(C))
    return;

  const Expr *E = RS->getRetValue();
  if (!E)
    return;

  const Expr *SimpE = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SimpE);
  if (!DRE)
    return;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  const MemRegion *MR = getVarRegion(VD, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Assigned = State->get<StatusVarAssignedMap>(MR);

  // If we tracked it and it is still unassigned -> bug
  if (Assigned && !*Assigned) {
    reportUninitializedReturn(VD, MR, RS, C);
    return;
  }

  // If not tracked (e.g., missed DeclStmt), but it is a candidate, also warn.
  if (!Assigned && isCandidateStatusVar(VD, C)) {
    reportUninitializedReturn(VD, MR, RS, C);
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects returning an uninitialized local status variable (e.g., 'ret')",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
