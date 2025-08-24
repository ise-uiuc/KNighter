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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Speculative read before guard", "Concurrency")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:

      // Helper to get the immediate previous sibling statement of an IfStmt within its enclosing CompoundStmt.
      const Stmt *getPrevSiblingStmt(const IfStmt *IS, CheckerContext &C) const;

      // Helper to check if guard is in acceptable simple forms.
      bool isSimpleGuardExpr(const Expr *Guard, CheckerContext &C) const;

      // Helper: whether expression references a specific VarDecl.
      bool exprReferencesVar(const Expr *E, const VarDecl *VD) const;

      // Helper: detect risky reads (deref/array subscript/ptr->field or kernel-specific call).
      bool containsRiskyAccess(const Expr *E, CheckerContext &C) const;

      // Emit report
      void reportBug(const Expr *AssignedExpr, const IfStmt *IS, CheckerContext &C) const;
};

static bool isZeroIntegerLiteral(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
    return IL->getValue() == 0;
  }
  return false;
}

const Stmt *SAGenTestChecker::getPrevSiblingStmt(const IfStmt *IS, CheckerContext &C) const {
  if (!IS) return nullptr;
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS) return nullptr;

  const Stmt *Prev = nullptr;
  for (const Stmt *S : CS->body()) {
    if (S == IS) {
      return Prev;
    }
    Prev = S;
  }
  return nullptr;
}

bool SAGenTestChecker::exprReferencesVar(const Expr *E, const VarDecl *VD) const {
  if (!E || !VD) return false;

  // Check the current node after ignoring implicit constructs
  const Expr *EI = E->IgnoreImplicit();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(EI)) {
    if (DRE->getDecl() == VD)
      return true;
  }

  // Recurse into children
  for (const Stmt *Child : E->children()) {
    const Expr *CE = dyn_cast_or_null<Expr>(Child);
    if (CE && exprReferencesVar(CE, VD))
      return true;
  }
  return false;
}

bool SAGenTestChecker::containsRiskyAccess(const Expr *E, CheckerContext &C) const {
  if (!E) return false;

  // Heuristic: kernel-specific helper name
  if (ExprHasName(E, "work_data_bits", C))
    return true;

  const Expr *EI = E->IgnoreImplicit();

  if (const auto *UO = dyn_cast<UnaryOperator>(EI)) {
    if (UO->getOpcode() == UO_Deref)
      return true;
  }

  if (isa<ArraySubscriptExpr>(EI))
    return true;

  if (const auto *ME = dyn_cast<MemberExpr>(EI)) {
    if (ME->isArrow())
      return true;
  }

  // Recurse
  for (const Stmt *Child : EI->children()) {
    const Expr *CE = dyn_cast_or_null<Expr>(Child);
    if (CE && containsRiskyAccess(CE, C))
      return true;
  }

  return false;
}

bool SAGenTestChecker::isSimpleGuardExpr(const Expr *Guard, CheckerContext &C) const {
  if (!Guard) return false;
  Guard = Guard->IgnoreParenImpCasts();

  // Case 1: Simple variable
  if (isa<DeclRefExpr>(Guard))
    return true;

  // Case 2: !var
  if (const auto *UO = dyn_cast<UnaryOperator>(Guard)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (isa<DeclRefExpr>(Sub))
        return true;
    }
  }

  // Case 3: var == 0/null or var != 0/null (also support 0 == var pattern)
  if (const auto *BO = dyn_cast<BinaryOperator>(Guard)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsZeroOrNull = isZeroIntegerLiteral(LHS) ||
        LHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsZeroOrNull = isZeroIntegerLiteral(RHS) ||
        RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsZeroOrNull && isa<DeclRefExpr>(RHS))
        return true;
      if (RHSIsZeroOrNull && isa<DeclRefExpr>(LHS))
        return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportBug(const Expr *AssignedExpr, const IfStmt *IS, CheckerContext &C) const {
  if (!BT) return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unconditional read occurs before guard; move the dereference under the guarded path.", N);

  if (AssignedExpr)
    R->addRange(AssignedExpr->getSourceRange());
  if (IS && IS->getCond())
    R->addRange(IS->getCond()->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // We only analyze IfStmt conditions.
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *IfCond = IS->getCond();
  if (!IfCond)
    return;

  // Ensure this callback is for the condition expression of this IfStmt.
  if (IfCond->IgnoreImplicit() != CondE->IgnoreImplicit())
    return;

  // We look for 'guard && rest'
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE->IgnoreParenImpCasts());
  if (!BO || BO->getOpcode() != BO_LAnd)
    return;

  const Expr *Guard = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *Rest  = BO->getRHS()->IgnoreParenImpCasts();

  if (!isSimpleGuardExpr(Guard, C))
    return;

  // Find the immediate previous statement to this IfStmt
  const Stmt *Prev = getPrevSiblingStmt(IS, C);
  if (!Prev)
    return;

  // Case 1: Declaration with initializer
  const VarDecl *DefinedVD = nullptr;
  const Expr *AssignedExpr = nullptr;

  if (const auto *DS = dyn_cast<DeclStmt>(Prev)) {
    if (!DS->isSingleDecl())
      return;
    const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
    if (!VD || !VD->hasInit())
      return;
    if (!VD->hasLocalStorage())
      return;

    DefinedVD = VD;
    AssignedExpr = VD->getInit();
  } else {
    // Case 2: Assignment expression statement immediately preceding
    // The child may be wrapped; use helper to find a BinaryOperator inside
    const BinaryOperator *AssignBO = findSpecificTypeInChildren<BinaryOperator>(Prev);
    if (!AssignBO || AssignBO->getOpcode() != BO_Assign)
      return;

    const Expr *LHS = AssignBO->getLHS()->IgnoreParenImpCasts();
    const auto *LHSRef = dyn_cast<DeclRefExpr>(LHS);
    if (!LHSRef)
      return;

    const auto *VD = dyn_cast<VarDecl>(LHSRef->getDecl());
    if (!VD || !VD->hasLocalStorage())
      return;

    DefinedVD = VD;
    AssignedExpr = AssignBO->getRHS();
  }

  if (!DefinedVD || !AssignedExpr)
    return;

  AssignedExpr = AssignedExpr->IgnoreParenImpCasts();

  // Ensure that the RHS of '&&' actually uses the defined variable
  if (!exprReferencesVar(Rest, DefinedVD))
    return;

  // The assignment should contain a risky access (deref / arr subscript / ptr->field)
  if (!containsRiskyAccess(AssignedExpr, C))
    return;

  // All checks passed: report bug.
  reportBug(AssignedExpr, IS, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects speculative reads placed before a guarding condition (e.g., data race prone read before 'guard && ...')",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
