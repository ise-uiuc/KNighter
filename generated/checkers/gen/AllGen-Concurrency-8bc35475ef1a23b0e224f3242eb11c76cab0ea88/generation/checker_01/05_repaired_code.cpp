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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary for this checker.

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unconditional shared read before guard",
                       "Concurrency")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  static const BinaryOperator *getTopLevelLogicalAnd(const Expr *E);
  static bool isNonConstantExpr(const Expr *E, ASTContext &ACtx);
  static void collectVarsInExpr(const Expr *E,
                                llvm::SmallPtrSet<const VarDecl *, 8> &Out);
  static bool exprReferencesVar(const Expr *E, const VarDecl *VD);
  static bool containsReadOnce(const Expr *E, CheckerContext &C);
  static bool containsCallNamed(const Expr *E, StringRef Name,
                                CheckerContext &C);
  static bool containsMemberNamedData(const Expr *E);
  static bool containsDerefLike(const Expr *E);
  static bool refersToParamOrGlobal(const Expr *E);

  static const Expr *getAssignmentRHSIfAssigningVar(const Stmt *S,
                                                    const VarDecl *TargetVD);
  static const Expr *getInitExprIfDeclaringVar(const Stmt *S,
                                               const VarDecl *TargetVD);
  void report(const Expr *ReadE, const Expr *GuardE, CheckerContext &C) const;
};

const BinaryOperator *SAGenTestChecker::getTopLevelLogicalAnd(const Expr *E) {
  if (!E)
    return nullptr;
  const Expr *I = E->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(I)) {
    if (BO->getOpcode() == BO_LAnd)
      return BO;
  }
  return nullptr;
}

bool SAGenTestChecker::isNonConstantExpr(const Expr *E, ASTContext &ACtx) {
  if (!E)
    return false;
  // If it's an integer constant expression, treat as constant guard (not useful).
  if (E->isIntegerConstantExpr(ACtx))
    return false;
  return true;
}

void SAGenTestChecker::collectVarsInExpr(
    const Expr *E, llvm::SmallPtrSet<const VarDecl *, 8> &Out) {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      Out.insert(VD);
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child))
      collectVarsInExpr(CE, Out);
  }
}

bool SAGenTestChecker::exprReferencesVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child))
      if (exprReferencesVar(CE, VD))
        return true;
  }
  return false;
}

bool SAGenTestChecker::containsReadOnce(const Expr *E, CheckerContext &C) {
  return ExprHasName(E, "READ_ONCE", C);
}

bool SAGenTestChecker::containsCallNamed(const Expr *E, StringRef Name,
                                         CheckerContext &C) {
  return ExprHasName(E, Name, C);
}

bool SAGenTestChecker::containsMemberNamedData(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const ValueDecl *VD = ME->getMemberDecl()) {
      if (VD->getName().contains("data"))
        return true;
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child))
      if (containsMemberNamedData(CE))
        return true;
  }
  return false;
}

bool SAGenTestChecker::containsDerefLike(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref)
      return true;
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    (void)ASE;
    return true;
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->isArrow())
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child))
      if (containsDerefLike(CE))
        return true;
  }
  return false;
}

bool SAGenTestChecker::refersToParamOrGlobal(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    if (isa<ParmVarDecl>(VD))
      return true;
    if (const auto *V = dyn_cast<VarDecl>(VD)) {
      if (V->hasGlobalStorage())
        return true;
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child))
      if (refersToParamOrGlobal(CE))
        return true;
  }
  return false;
}

const Expr *SAGenTestChecker::getAssignmentRHSIfAssigningVar(
    const Stmt *S, const VarDecl *TargetVD) {
  if (!S || !TargetVD)
    return nullptr;

  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return nullptr;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  if (const auto *LHSRef = dyn_cast<DeclRefExpr>(LHS)) {
    if (LHSRef->getDecl() == TargetVD)
      return BO->getRHS();
  }
  return nullptr;
}

const Expr *SAGenTestChecker::getInitExprIfDeclaringVar(
    const Stmt *S, const VarDecl *TargetVD) {
  if (!S || !TargetVD)
    return nullptr;

  const auto *DS = dyn_cast<DeclStmt>(S);
  if (!DS)
    return nullptr;

  for (const Decl *D : DS->decls()) {
    if (const auto *VD = dyn_cast<VarDecl>(D)) {
      if (VD == TargetVD && VD->hasInit())
        return VD->getInit();
    }
  }
  return nullptr;
}

void SAGenTestChecker::report(const Expr *ReadE, const Expr *GuardE,
                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unconditional read of shared state before guard; move the read under "
      "the guard to avoid races",
      N);

  if (ReadE)
    R->addRange(ReadE->getSourceRange());
  if (GuardE)
    R->addRange(GuardE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const auto *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  const auto *TopAnd = getTopLevelLogicalAnd(CondE);
  if (!TopAnd)
    return;

  const Expr *LHS = TopAnd->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = TopAnd->getRHS()->IgnoreParenImpCasts();
  if (!LHS || !RHS)
    return;

  // Basic sanity/heuristic: LHS should be a non-constant "guard"-like expr.
  if (!isNonConstantExpr(LHS, C.getASTContext()))
    return;

  // Collect variables used on RHS of &&
  llvm::SmallPtrSet<const VarDecl *, 8> RHSVars;
  collectVarsInExpr(RHS, RHSVars);
  if (RHSVars.empty())
    return;

  // Locate the containing IfStmt
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  // Locate the parent compound statement to find the previous sibling
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
  if (!CS)
    return;

  const Stmt *PrevS = nullptr;
  for (auto I = CS->body_begin(), E = CS->body_end(); I != E; ++I) {
    if (*I == IfS) {
      if (I != CS->body_begin()) {
        PrevS = *(I - 1);
      }
      break;
    }
  }
  if (!PrevS)
    return;

  // For each variable used on the RHS, check if PrevS assigns/initializes it
  // via a raw memory read (without READ_ONCE).
  for (const VarDecl *VD : RHSVars) {
    // Avoid cases where the guard itself references the variable (self-guarded).
    if (exprReferencesVar(LHS, VD))
      continue;

    const Expr *SuspiciousRead = nullptr;

    if (const Expr *R = getAssignmentRHSIfAssigningVar(PrevS, VD)) {
      SuspiciousRead = R;
    } else if (const Expr *R = getInitExprIfDeclaringVar(PrevS, VD)) {
      SuspiciousRead = R;
    }

    if (!SuspiciousRead)
      continue;

    // Heuristics to decide it's a likely unsynchronized shared read:
    // - It's a deref-like expression OR contains a member named 'data'
    //   OR calls a function like work_data_bits.
    // - It does NOT contain READ_ONCE (already atomic).
    // - It refers to a parameter or global somewhere (shared input).
    bool RawLike = containsDerefLike(SuspiciousRead) ||
                   containsMemberNamedData(SuspiciousRead) ||
                   containsCallNamed(SuspiciousRead, "work_data_bits", C);

    if (!RawLike)
      continue;

    if (containsReadOnce(SuspiciousRead, C))
      continue;

    if (!refersToParamOrGlobal(SuspiciousRead))
      continue;

    // Found the pattern: Unconditional raw read feeding the RHS of a guarded &&
    // condition. Report once per match.
    report(SuspiciousRead, LHS, C);
    // Prevent duplicate reports for multiple RHS vars in the same pattern.
    break;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unconditional reads of shared/concurrently-updated fields that "
      "occur before a guarding condition (e.g., reading work->data before "
      "checking from_cancel)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
