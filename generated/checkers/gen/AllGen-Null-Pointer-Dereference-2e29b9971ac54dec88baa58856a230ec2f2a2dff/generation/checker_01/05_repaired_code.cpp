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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state required.

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Incorrect NULL-check after allocation", "Logic")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      bool isAllocLikeCall(const CallExpr *CE, CheckerContext &C) const;
      bool isNullLiteral(const Expr *E, CheckerContext &C) const;
      const Expr *extractCheckedPointerFromCondition(const Expr *E, CheckerContext &C) const;
      const Stmt *getPrevStmtInSameCompound(const IfStmt *IfS, CheckerContext &C) const;
      const BinaryOperator *getAssignFromStmt(const Stmt *S) const;
      const CallExpr *getAllocCallFromRHS(const Expr *RHS, CheckerContext &C) const;
      const MemRegion *getMemRegionOfExpr(const Expr *E, CheckerContext &C) const;
};

// Check if a call expression calls an allocation-like function we care about.
bool SAGenTestChecker::isAllocLikeCall(const CallExpr *CE, CheckerContext &C) const {
  if (!CE)
    return false;
  const Expr *CalleeE = CE->getCallee();
  if (!CalleeE)
    return false;

  // Use ExprHasName utility for robustness.
  static const char *AllocNames[] = {
      "kzalloc", "kmalloc", "kcalloc", "kvzalloc", "devm_kzalloc", "kmemdup"
  };

  for (const char *Name : AllocNames) {
    if (ExprHasName(CalleeE, Name, C))
      return true;
  }
  return false;
}

// Determine if an expression represents a NULL literal or zero.
bool SAGenTestChecker::isNullLiteral(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();

  // Check null pointer constant via AST API.
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

  // Try to evaluate to int constant 0.
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C)) {
    if (Val == 0)
      return true;
  }

  // Fallback: textual match of "NULL" in source.
  if (ExprHasName(E, "NULL", C))
    return true;

  return false;
}

// Extract the pointer expression being negatively checked for NULL.
// Only accept: !ptr or (ptr == NULL). We ignore (ptr != NULL).
const Expr *SAGenTestChecker::extractCheckedPointerFromCondition(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenCasts();

  // !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      if (!Sub)
        return nullptr;
      return Sub->IgnoreParenCasts();
    }
    return nullptr;
  }

  // ptr == NULL
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSNull = isNullLiteral(LHS, C);
      bool RHSNull = isNullLiteral(RHS, C);

      if (LHSNull ^ RHSNull) {
        // Return the non-null side
        return LHSNull ? RHS : LHS;
      }
    }
    // Ignore ptr != NULL (positive check)
    return nullptr;
  }

  return nullptr;
}

// Find the previous statement in the same compound block as the IfStmt.
const Stmt *SAGenTestChecker::getPrevStmtInSameCompound(const IfStmt *IfS, CheckerContext &C) const {
  if (!IfS)
    return nullptr;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
  if (!CS)
    return nullptr;

  const Stmt *Prev = nullptr;
  for (auto It = CS->body_begin(); It != CS->body_end(); ++It) {
    const Stmt *Cur = *It;
    if (Cur == IfS) {
      return Prev;
    }
    Prev = Cur;
  }
  return nullptr;
}

// From a statement, find a BinaryOperator that is an assignment.
const BinaryOperator *SAGenTestChecker::getAssignFromStmt(const Stmt *S) const {
  if (!S)
    return nullptr;
  const BinaryOperator *BO = findSpecificTypeInChildren<BinaryOperator>(S);
  if (!BO)
    return nullptr;
  if (BO->getOpcode() == BO_Assign)
    return BO;
  return nullptr;
}

// From RHS expression, find a CallExpr of known allocation functions.
const CallExpr *SAGenTestChecker::getAllocCallFromRHS(const Expr *RHS, CheckerContext &C) const {
  if (!RHS)
    return nullptr;
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(RHS);
  if (!CE)
    return nullptr;
  if (isAllocLikeCall(CE, C))
    return CE;
  return nullptr;
}

// Get base MemRegion of the expression.
const MemRegion *SAGenTestChecker::getMemRegionOfExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Extract pointer being negatively checked for NULL (only !ptr or ptr == NULL)
  const Expr *CheckedPtrExpr = extractCheckedPointerFromCondition(CondE, C);
  if (!CheckedPtrExpr)
    return;

  // Get previous statement in the same compound block.
  const Stmt *Prev = getPrevStmtInSameCompound(IfS, C);
  if (!Prev)
    return;

  // Get an assignment in the previous statement.
  const BinaryOperator *BO = getAssignFromStmt(Prev);
  if (!BO)
    return;

  // Check if RHS is an allocation-like call.
  const CallExpr *AllocCE = getAllocCallFromRHS(BO->getRHS(), C);
  if (!AllocCE)
    return;

  // Get regions of LHS (allocated pointer) and the pointer being checked.
  const MemRegion *LHSReg = getMemRegionOfExpr(BO->getLHS(), C);
  const MemRegion *CheckedReg = getMemRegionOfExpr(CheckedPtrExpr, C);
  if (!LHSReg || !CheckedReg)
    return;

  // If they differ, we have the target pattern.
  if (LHSReg != CheckedReg) {
    // Optional: reduce noise, require an error path in 'then' branch.
    const ReturnStmt *RetInThen = findSpecificTypeInChildren<ReturnStmt>(IfS->getThen());
    if (!RetInThen)
      return;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Allocated pointer checked via a different pointer; possible missed NULL-check.", N);
    R->addRange(IfS->getCond()->getSourceRange());

    const SourceManager &SM = C.getSourceManager();
    const LocationContext *LCtx = C.getLocationContext();

    PathDiagnosticLocation PrevLoc = PathDiagnosticLocation::createBegin(Prev, SM, LCtx);
    R->addNote("Allocation assigned to this pointer", PrevLoc);

    PathDiagnosticLocation CondLoc = PathDiagnosticLocation::createBegin(IfS->getCond(), SM, LCtx);
    R->addNote("But NULL-check tests a different pointer", CondLoc);

    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects checking a different pointer after allocation (missed NULL-check)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
