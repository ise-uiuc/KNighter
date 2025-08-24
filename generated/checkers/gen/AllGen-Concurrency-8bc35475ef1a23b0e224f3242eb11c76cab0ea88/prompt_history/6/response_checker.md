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
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtCXX.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map a local VarRegion (the receiver variable) to the statement that performed
// the suspicious speculative load (assignment/init).
REGISTER_MAP_WITH_PROGRAMSTATE(SpeculativeLoadMap, const VarRegion *, const Stmt *)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::BranchCondition,
        check::EndFunction
      > {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Speculative unguarded read", "Concurrency")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Returns true if RHS matches the suspicious pattern "*call(args...)" and
  // the call's first argument refers to a shared location (param/global).
  bool analyzeAssignment(const VarDecl *VD, const Expr *RHS,
                         const Stmt *BindSite, CheckerContext &C) const;

  // Utility: collect local (automatic storage) VarDecls referenced in E.
  void collectLocalVarDeclsInExpr(const Expr *E,
                                  llvm::SmallVectorImpl<const VarDecl*> &Out) const;

  // Utility: verify destination variable kind is acceptable (local, scalar or pointer).
  bool isLocalScalarOrPointerVar(const VarDecl *VD, ASTContext &ACtx) const;

  // Report diagnostic at the speculative load statement.
  void reportAtLoad(const Stmt *LoadS, const IfStmt *IfS, CheckerContext &C) const;

  // Check if IfS is immediately following LoadS inside the same compound block.
  bool isImmediatelyBefore(const Stmt *Prev, const IfStmt *IfS, CheckerContext &C) const;
};

bool SAGenTestChecker::isLocalScalarOrPointerVar(const VarDecl *VD, ASTContext &ACtx) const {
  if (!VD)
    return false;
  if (!VD->hasLocalStorage())
    return false;
  QualType QT = VD->getType();
  if (QT.isNull())
    return false;
  return QT->isScalarType() || QT->isPointerType() || QT->isIntegerType();
}

void SAGenTestChecker::collectLocalVarDeclsInExpr(const Expr *E,
    llvm::SmallVectorImpl<const VarDecl*> &Out) const {
  if (!E) return;
  struct Walker {
    static void run(const Expr *Node, llvm::SmallVectorImpl<const VarDecl*> &Out) {
      if (!Node) return;
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Node->IgnoreParenCasts())) {
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (VD->hasLocalStorage())
            Out.push_back(VD);
        }
      }
      for (const Stmt *Child : Node->children()) {
        if (const auto *CE = dyn_cast_or_null<Expr>(Child))
          run(CE, Out);
      }
    }
  };
  Walker::run(E, Out);
}

bool SAGenTestChecker::analyzeAssignment(const VarDecl *VD, const Expr *RHS,
                                         const Stmt *BindSite, CheckerContext &C) const {
  if (!VD || !RHS || !BindSite)
    return false;

  if (!isLocalScalarOrPointerVar(VD, C.getASTContext()))
    return false;

  // Skip if expression explicitly uses READ_ONCE or 'atomic' markers.
  if (ExprHasName(RHS, "READ_ONCE", C) || ExprHasName(RHS, "atomic", C))
    return false;

  // Look for a unary '*' dereference of a call expression.
  const UnaryOperator *UO = findSpecificTypeInChildren<UnaryOperator>(RHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return false;

  const Expr *Sub = UO->getSubExpr();
  if (!Sub)
    return false;
  Sub = Sub->IgnoreParenCasts();

  const CallExpr *CE = dyn_cast<CallExpr>(Sub);
  if (!CE)
    return false;

  // Heuristic: first argument should refer to a parameter or global storage.
  if (CE->getNumArgs() > 0) {
    const Expr *A0 = CE->getArg(0);
    if (!A0)
      return false;

    const MemRegion *R = getMemRegionFromExpr(A0, C);
    if (!R)
      return false;
    R = R->getBaseRegion();
    if (!R)
      return false;

    if (isa<ParamRegion>(R)) {
      // OK, likely shared via parameter.
    } else if (const auto *VR = dyn_cast<VarRegion>(R)) {
      const VarDecl *SrcVD = VR->getDecl();
      if (!SrcVD || !SrcVD->hasGlobalStorage())
        return false;
    } else {
      // Unknown source - be conservative and skip.
      return false;
    }
  } else {
    // No arguments - less likely to be shared; be conservative.
    return false;
  }

  return true;
}

bool SAGenTestChecker::isImmediatelyBefore(const Stmt *Prev, const IfStmt *IfS, CheckerContext &C) const {
  if (!Prev || !IfS)
    return false;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
  if (!CS)
    return false;

  const Stmt *Last = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (Child == IfS)
      return Last == Prev;
    Last = Child;
  }
  return false;
}

void SAGenTestChecker::reportAtLoad(const Stmt *LoadS, const IfStmt *IfS, CheckerContext &C) const {
  if (!LoadS)
    return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Speculative unguarded read; move the read under the guard", N);
  R->addRange(LoadS->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  ProgramStateRef State = C.getState();
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    if (!analyzeAssignment(VD, Init, DS, C))
      continue;

    const VarRegion *VR = MRMgr.getVarRegion(VD, C.getLocationContext());
    if (!VR)
      continue;

    State = State->set<SpeculativeLoadMap>(VR, DS);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  const auto *DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenCasts());
  if (!DRE)
    return;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  if (!isLocalScalarOrPointerVar(VD, C.getASTContext()))
    return;

  if (!analyzeAssignment(VD, RHS, S, C))
    return;

  ProgramStateRef State = C.getState();
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const VarRegion *VR = MRMgr.getVarRegion(VD, C.getLocationContext());
  if (!VR)
    return;

  State = State->set<SpeculativeLoadMap>(VR, S);
  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  const Expr *CondE = IfS->getCond();
  if (!CondE)
    return;
  CondE = CondE->IgnoreParenCasts();

  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO || BO->getOpcode() != BO_LAnd)
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // Collect local variables referenced on RHS.
  llvm::SmallVector<const VarDecl*, 8> RHSVars;
  collectLocalVarDeclsInExpr(RHS, RHSVars);

  if (RHSVars.empty())
    return;

  ProgramStateRef State = C.getState();
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();

  for (const VarDecl *VD : RHSVars) {
    if (!VD)
      continue;

    const VarRegion *VR = MRMgr.getVarRegion(VD, C.getLocationContext());
    if (!VR)
      continue;

    const Stmt *const *LoadSP = State->get<SpeculativeLoadMap>(VR);
    if (!LoadSP)
      continue;

    const Stmt *LoadS = *LoadSP;
    if (!LoadS)
      continue;

    // Ensure the variable is not referenced in the guard (LHS).
    if (ExprHasName(LHS, VD->getName(), C))
      continue;

    // Ensure adjacency: the 'if' immediately follows the load statement.
    if (!isImmediatelyBefore(LoadS, IfS, C))
      continue;

    // Report the issue at the speculative load site.
    reportAtLoad(LoadS, IfS, C);

    // Remove the entry to avoid duplicate reports.
    State = State->remove<SpeculativeLoadMap>(VR);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // No explicit clearing is necessary; function-local regions die at function exit.
  // Kept for completeness per plan.
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects speculative unguarded reads before guard checks (e.g., reading shared state before testing a guard such as from_cancel)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
