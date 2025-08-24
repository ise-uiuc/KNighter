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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track the object pointer that gets published into a global ID registry.
// Key: MemRegion of the pointer variable passed to publish API (e.g., xa_alloc third arg).
// Val: the Stmt* of the publish call (for diagnostics).
REGISTER_MAP_WITH_PROGRAMSTATE(PublishedMap, const MemRegion*, const Stmt*)
// Avoid duplicate reports for the same region.
REGISTER_SET_WITH_PROGRAMSTATE(ReportedSet, const MemRegion*)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<
  check::PostCall,
  check::PreCall,
  check::Bind,
  check::EndFunction
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Publish-before-finalization (UAF risk)", "Use-after-free")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:

      // Helpers
      static bool isIoctlFunction(const CheckerContext &C);
      static bool isPublishCall(const CallEvent &Call, unsigned &PtrParamIndex, CheckerContext &C);
      static bool isPublishCallItself(const CallEvent &Call, const MemRegion *Published, CheckerContext &C);
      static const MemRegion* getVarRegionFromArg(const Expr *E, CheckerContext &C);
      static const VarDecl* getVarDeclFromRegion(const MemRegion *R);
      static bool containsDeclRefToVD(const Stmt *S, const VarDecl *VD);
      static bool exprContainsVarDecl(const Expr *E, const VarDecl *VD);
      static bool exprIsWriteThroughVar(const Expr *E, const VarDecl *VD);
      static void addPublishNote(PathSensitiveBugReport &R, const Stmt *PubStmt, CheckerContext &C);
};

bool SAGenTestChecker::isIoctlFunction(const CheckerContext &C) {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;
  const Decl *D = LCtx->getDecl();
  if (!D)
    return false;
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return false;
  StringRef Name = FD->getName();
  if (Name.empty())
    return false;
  std::string Lower = Name.lower();
  return Lower.find("ioctl") != std::string::npos;
}

bool SAGenTestChecker::isPublishCall(const CallEvent &Call, unsigned &PtrParamIndex, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // xarray
  if (ExprHasName(Origin, "xa_alloc", C)) {
    PtrParamIndex = 2;
    return true;
  }
  if (ExprHasName(Origin, "xa_alloc_cyclic", C)) {
    PtrParamIndex = 2;
    return true;
  }

  // idr
  if (ExprHasName(Origin, "idr_alloc", C)) {
    PtrParamIndex = 1;
    return true;
  }
  if (ExprHasName(Origin, "idr_alloc_u32", C)) {
    PtrParamIndex = 1;
    return true;
  }
  if (ExprHasName(Origin, "idr_alloc_cyclic", C)) {
    PtrParamIndex = 1;
    return true;
  }

  return false;
}

const MemRegion* SAGenTestChecker::getVarRegionFromArg(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;
  if (!isa<VarRegion>(MR))
    return nullptr;
  return MR;
}

const VarDecl* SAGenTestChecker::getVarDeclFromRegion(const MemRegion *R) {
  if (!R)
    return nullptr;
  if (const auto *VR = dyn_cast<VarRegion>(R))
    return VR->getDecl();
  return nullptr;
}

bool SAGenTestChecker::containsDeclRefToVD(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (DRE->getDecl() == VD)
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsDeclRefToVD(Child, VD))
      return true;
  }
  return false;
}

bool SAGenTestChecker::exprContainsVarDecl(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  return containsDeclRefToVD(E, VD);
}

bool SAGenTestChecker::exprIsWriteThroughVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  const Expr *EE = E->IgnoreParenCasts();

  // q->field or q.field
  if (const auto *ME = dyn_cast<MemberExpr>(EE)) {
    const Expr *Base = ME->getBase();
    if (exprContainsVarDecl(Base, VD))
      return true;
  }

  // *q = ...
  if (const auto *UO = dyn_cast<UnaryOperator>(EE)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr();
      if (exprContainsVarDecl(Sub, VD))
        return true;
    }
  }

  // q[i] = ...
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(EE)) {
    const Expr *Base = ASE->getBase();
    if (exprContainsVarDecl(Base, VD))
      return true;
  }

  // We intentionally do NOT treat a bare DeclRefExpr (i.e., "q = ...") as a write-through.
  return false;
}

bool SAGenTestChecker::isPublishCallItself(const CallEvent &Call, const MemRegion *Published, CheckerContext &C) {
  unsigned PI = 0;
  if (!isPublishCall(Call, PI, C))
    return false;
  if (PI >= Call.getNumArgs())
    return false;

  const Expr *ArgE = Call.getArgExpr(PI);
  const MemRegion *MR = getVarRegionFromArg(ArgE, C);
  if (!MR)
    return false;
  return MR->getBaseRegion() == Published->getBaseRegion();
}

void SAGenTestChecker::addPublishNote(PathSensitiveBugReport &R, const Stmt *PubStmt, CheckerContext &C) {
  if (!PubStmt)
    return;
  PathDiagnosticLocation PubLoc =
      PathDiagnosticLocation::createBegin(PubStmt, C.getSourceManager(), C.getLocationContext());
  R.addNote("Object published here (xa/id alloc)", PubLoc);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isIoctlFunction(C))
    return;

  unsigned PtrIndex = 0;
  if (!isPublishCall(Call, PtrIndex, C))
    return;

  if (PtrIndex >= Call.getNumArgs())
    return;

  const Expr *ArgE = Call.getArgExpr(PtrIndex);
  const MemRegion *MR = getVarRegionFromArg(ArgE, C);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const Stmt *S = Call.getOriginExpr();
  if (!S)
    return;

  // Record that MR has been published at S.
  State = State->set<PublishedMap>(MR->getBaseRegion(), S);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isIoctlFunction(C))
    return;

  ProgramStateRef State = C.getState();
  const auto *PM = State->get<PublishedMap>();
  if (!PM || PM->empty())
    return;

  // Skip reporting on the publish call itself.
  // For other calls, if a published var is used as an argument, warn.
  for (auto It = PM->begin(); It != PM->end(); ++It) {
    const MemRegion *PubReg = It->first;
    const Stmt *PubStmt = It->second;

    if (State->contains<ReportedSet>(PubReg))
      continue;

    if (isPublishCallItself(Call, PubReg, C))
      continue;

    const VarDecl *VD = getVarDeclFromRegion(PubReg);
    if (!VD)
      continue;

    bool Used = false;
    for (unsigned i = 0, e = Call.getNumArgs(); i < e; ++i) {
      const Expr *ArgE = Call.getArgExpr(i);
      if (!ArgE)
        continue;
      if (exprContainsVarDecl(ArgE, VD)) {
        Used = true;
        break;
      }
    }

    if (Used) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto Rpt = std::make_unique<PathSensitiveBugReport>(
          *BT, "Object used after publishing into ID registry; publish must be last in ioctl", N);
      Rpt->addRange(Call.getSourceRange());
      addPublishNote(*Rpt, PubStmt, C);
      C.emitReport(std::move(Rpt));

      State = State->add<ReportedSet>(PubReg);
      C.addTransition(State);
      // Only report once per call for the first matching published region.
      return;
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  if (!isIoctlFunction(C))
    return;

  ProgramStateRef State = C.getState();
  const auto *PM = State->get<PublishedMap>();
  if (!PM || PM->empty() || !StoreE)
    return;

  const BinaryOperator *BO = findSpecificTypeInChildren<BinaryOperator>(StoreE);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return;

  for (auto It = PM->begin(); It != PM->end(); ++It) {
    const MemRegion *PubReg = It->first;
    const Stmt *PubStmt = It->second;

    if (State->contains<ReportedSet>(PubReg))
      continue;

    const VarDecl *VD = getVarDeclFromRegion(PubReg);
    if (!VD)
      continue;

    if (exprIsWriteThroughVar(LHS, VD)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Rpt = std::make_unique<PathSensitiveBugReport>(
          *BT, "ID allocated before final initialization; publish must be last to avoid UAF", N);
      Rpt->addRange(StoreE->getSourceRange());
      addPublishNote(*Rpt, PubStmt, C);
      C.emitReport(std::move(Rpt));

      State = State->add<ReportedSet>(PubReg);
      C.addTransition(State);
      return;
    }
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->remove<PublishedMap>();
  State = State->remove<ReportedSet>();
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing objects into ID registries before final initialization (UAF risk) in ioctl paths",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
