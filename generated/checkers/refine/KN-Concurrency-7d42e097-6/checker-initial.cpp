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
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states required for this checker.

namespace {

static const FunctionDecl *getDirectCallee(const CallExpr *CE) {
  if (!CE) return nullptr;
  return CE->getDirectCallee();
}

static StringRef getCalleeName(const CallExpr *CE) {
  if (const FunctionDecl *FD = getDirectCallee(CE)) {
    if (const IdentifierInfo *II = FD->getIdentifier())
      return II->getName();
  }
  return StringRef();
}

static const VarDecl *getVarDeclFromDeclRefBase(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
  }
  return nullptr;
}

// Extract the base variable from an argument that looks like &ctx->compl or ctx->compl
static const VarDecl *extractBaseVarFromComplArg(const Expr *Arg) {
  if (!Arg) return nullptr;
  const Expr *E = Arg->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_AddrOf)
      E = UO->getSubExpr()->IgnoreParenImpCasts();
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    const ValueDecl *Member = ME->getMemberDecl();
    if (!Member) return nullptr;
    // We expect field named 'compl' (Linux completion field)
    if (Member->getIdentifier() && Member->getName().equals("compl")) {
      const Expr *Base = ME->getBase();
      if (!Base) return nullptr;
      return getVarDeclFromDeclRefBase(Base);
    }
  }
  return nullptr;
}

static const VarDecl *extractVarFromExprSimple(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
  }
  return nullptr;
}

static bool isWorkHandler(const FunctionDecl *FD) {
  if (!FD) return false;
  if (!FD->hasBody()) return false;
  if (FD->param_size() < 1) return false;

  const ParmVarDecl *P0 = FD->getParamDecl(0);
  if (!P0) return false;

  QualType QT = P0->getType();
  if (!QT->isPointerType()) return false;

  QualType Pointee = QT->getPointeeType();
  if (const auto *RT = Pointee->getAs<RecordType>()) {
    const RecordDecl *RD = RT->getDecl();
    if (const IdentifierInfo *II = RD->getIdentifier()) {
      // We expect 'work_struct'
      if (II->getName().equals("work_struct"))
        return true;
    }
  }
  // Fallback heuristic (rarely needed) - rely on type spelling
  std::string S;
  llvm::raw_string_ostream OS(S);
  QT.print(OS, PrintingPolicy(FD->getASTContext().getLangOpts()));
  OS.flush();
  return (S.find("work_struct *") != std::string::npos);
}

// Recursively check for kfree(var) inside a statement subtree.
static bool containsKfreeOfVar(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD) return false;
  for (const Stmt *Child : S->children()) {
    if (!Child) continue;
    if (const auto *CE = dyn_cast<CallExpr>(Child)) {
      StringRef Callee = getCalleeName(CE);
      if (Callee.equals("kfree") && CE->getNumArgs() >= 1) {
        const VarDecl *ArgVD = extractVarFromExprSimple(CE->getArg(0));
        if (ArgVD == VD)
          return true;
      }
    }
    if (containsKfreeOfVar(Child, VD))
      return true;
  }
  return false;
}

// Visitor to scan work handler function body for usage/free/guard patterns.
class WorkerVisitor : public RecursiveASTVisitor<WorkerVisitor> {
public:
  WorkerVisitor(llvm::SmallPtrSetImpl<const VarDecl*> &CtxVars,
                bool &UsedComplete, bool &UsedKfree, bool &HasGuard)
      : ObservedCtxVars(CtxVars), UsedComplete(UsedComplete),
        UsedKfree(UsedKfree), HasGuard(HasGuard) {}

  bool VisitCallExpr(CallExpr *CE) {
    StringRef Name = getCalleeName(CE);
    if (Name.empty())
      return true;

    if ((Name.equals("complete") || Name.equals("complete_all")) && CE->getNumArgs() >= 1) {
      if (const VarDecl *Base = extractBaseVarFromComplArg(CE->getArg(0))) {
        ObservedCtxVars.insert(Base);
        UsedComplete = true;
      }
    } else if (Name.equals("completion_done") && CE->getNumArgs() >= 1) {
      if (const VarDecl *Base = extractBaseVarFromComplArg(CE->getArg(0))) {
        ObservedCtxVars.insert(Base);
        HasGuard = true;
      }
    } else if (Name.equals("kfree") && CE->getNumArgs() >= 1) {
      if (const VarDecl *V = extractVarFromExprSimple(CE->getArg(0))) {
        if (ObservedCtxVars.count(V))
          UsedKfree = true;
      }
    }

    return true;
  }

private:
  llvm::SmallPtrSetImpl<const VarDecl*> &ObservedCtxVars;
  bool &UsedComplete;
  bool &UsedKfree;
  bool &HasGuard;
};

class SAGenTestChecker : public Checker<check::ASTCodeBody, check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Work handler missing completion_done guard", "Concurrency")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helper to report AST-level issue (worker side).
      void reportWorker(const FunctionDecl *FD, BugReporter &BR) const;
      // Helper to report branch-based issue (submitter side).
      void reportSubmitter(const IfStmt *IfS, CheckerContext &C) const;
};

void SAGenTestChecker::reportWorker(const FunctionDecl *FD, BugReporter &BR) const {
  if (!BT || !FD) return;
  PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(FD, BR.getSourceManager());
  auto R = std::make_unique<BasicBugReport>(
      *BT, "work handler lacks completion_done() guard before using/freeing shared context", Loc);
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::reportSubmitter(const IfStmt *IfS, CheckerContext &C) const {
  if (!BT || !IfS) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "frees work context on timeout while worker may still use it", N);
  R->addRange(IfS->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  if (!isWorkHandler(FD))
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  llvm::SmallPtrSet<const VarDecl*, 4> ObservedCtxVars;
  bool UsedComplete = false;
  bool UsedKfree = false;
  bool HasGuard = false;

  WorkerVisitor V(ObservedCtxVars, UsedComplete, UsedKfree, HasGuard);
  V.TraverseStmt(Body);

  if ((UsedComplete || UsedKfree) && !HasGuard) {
    reportWorker(FD, BR);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;
  const auto *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) return;

  const Expr *E = CondE->IgnoreParenCasts();

  // Pattern: if (!wait_for_completion_timeout(&ctx->compl, ...)) { kfree(ctx); }
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_LNot)
    return;

  const Expr *Sub = UO->getSubExpr();
  if (!Sub) return;
  Sub = Sub->IgnoreParenCasts();

  const auto *CE = dyn_cast<CallExpr>(Sub);
  if (!CE) return;

  StringRef Callee = getCalleeName(CE);
  if (!Callee.equals("wait_for_completion_timeout"))
    return;

  if (CE->getNumArgs() < 1)
    return;

  const VarDecl *CtxVar = extractBaseVarFromComplArg(CE->getArg(0));
  if (!CtxVar)
    return;

  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS) return;

  const Stmt *Then = IfS->getThen();
  if (!Then) return;

  if (containsKfreeOfVar(Then, CtxVar)) {
    reportSubmitter(IfS, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing completion_done() guard in work handlers and free-on-timeout of shared work context",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
