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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallVector.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Mismatched NULL check after allocation",
                       "Logic error")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper recognizers
  bool isAllocatorCall(const CallExpr *CE, CheckerContext &C) const;

  bool isNullCheckTrueBranch(const Expr *Cond, const Expr *&CheckedPtrExpr,
                             CheckerContext &C) const;

  bool getAssignedLHSFromStmt(const Stmt *S, const Expr *&LHSExprOut,
                              const CallExpr *&AllocCallOut,
                              CheckerContext &C) const;

  bool regionEqual(const Expr *A, const Expr *B, CheckerContext &C) const;

  bool thenBranchReturnsENOMEM(const IfStmt *IfS, CheckerContext &C) const;
};

// Recognize allocator calls by name.
bool SAGenTestChecker::isAllocatorCall(const CallExpr *CE,
                                       CheckerContext &C) const {
  if (!CE)
    return false;

  static const char *AllocNames[] = {
      "kzalloc",       "kmalloc",       "kcalloc",     "kmalloc_array",
      "kcalloc_array", "kzalloc_node",  "devm_kzalloc","devm_kmalloc",
      "devm_kcalloc",
  };

  const Expr *CalleeE = CE->getCallee();
  for (const char *Name : AllocNames) {
    if (CalleeE && ExprHasName(CalleeE, Name, C))
      return true;
  }

  // Fallback to direct callee identifier if available.
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    StringRef N = FD->getName();
    for (const char *Name : AllocNames) {
      if (N.equals(Name))
        return true;
    }
  }

  return false;
}

// Determine if the condition's true branch corresponds to a NULL check.
// Extract the pointer expression being checked for NULL.
bool SAGenTestChecker::isNullCheckTrueBranch(const Expr *Cond,
                                             const Expr *&CheckedPtrExpr,
                                             CheckerContext &C) const {
  if (!Cond)
    return false;

  ASTContext &ACtx = C.getASTContext();
  Cond = Cond->IgnoreParenImpCasts();

  // if (!E)  ==> true branch when E is NULL
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      CheckedPtrExpr = UO->getSubExpr()->IgnoreParenImpCasts();
      return true;
    }
    return false;
  }

  // if (E1 == E2) where the other side is 0 or NULL
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() != BO_EQ)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    auto IsNullish = [&](const Expr *E) -> bool {
      if (!E)
        return false;
      // Prefer Clang's check for null pointer constants.
      if (E->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull))
        return true;

      // Try integer evaluation for literal 0
      llvm::APSInt Val;
      if (EvaluateExprToInt(Val, E, C))
        return Val == 0;

      // Check textual "NULL"
      if (ExprHasName(E, "NULL", C))
        return true;

      return false;
    };

    bool LIsNull = IsNullish(LHS);
    bool RIsNull = IsNullish(RHS);

    if (LIsNull ^ RIsNull) {
      CheckedPtrExpr = LIsNull ? RHS : LHS;
      return true;
    }
  }

  return false;
}

// From a statement, extract "LHS = allocator_call(...)" or "T LHS = allocator_call(...);"
bool SAGenTestChecker::getAssignedLHSFromStmt(const Stmt *S,
                                              const Expr *&LHSExprOut,
                                              const CallExpr *&AllocCallOut,
                                              CheckerContext &C) const {
  LHSExprOut = nullptr;
  AllocCallOut = nullptr;

  if (!S)
    return false;

  // Case 1: assignment statement
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (const auto *CE = dyn_cast<CallExpr>(RHS)) {
        if (isAllocatorCall(CE, C)) {
          LHSExprOut = BO->getLHS()->IgnoreParenImpCasts();
          AllocCallOut = CE;
          return true;
        }
      }
    }
  }

  // Case 2: declaration with initializer
  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    for (auto It = DS->decl_begin(); It != DS->decl_end(); ++It) {
      if (const auto *VD = dyn_cast<VarDecl>(*It)) {
        const Expr *Init = VD->getInit();
        if (!Init)
          continue;
        Init = Init->IgnoreParenImpCasts();
        if (const auto *CE = dyn_cast<CallExpr>(Init)) {
          if (isAllocatorCall(CE, C)) {
            // Create a DeclRefExpr for VD to use in region comparison
            ASTContext &Ctx = C.getASTContext();
            auto *NonConstVD = const_cast<VarDecl *>(VD);
            // Use a minimal constructor for DeclRefExpr
            LHSExprOut = DeclRefExpr::Create(
                Ctx, NestedNameSpecifierLoc(), SourceLocation(), NonConstVD,
                /*RefersToEnclosingVariableOrCapture*/ false, VD->getLocation(),
                VD->getType(), VK_LValue);
            AllocCallOut = CE;
            return true;
          }
        }
      }
    }
  }

  return false;
}

// Compare whether two expressions refer to the same base memory region.
bool SAGenTestChecker::regionEqual(const Expr *A, const Expr *B,
                                   CheckerContext &C) const {
  if (!A || !B)
    return false;

  const MemRegion *RA = getMemRegionFromExpr(A, C);
  const MemRegion *RB = getMemRegionFromExpr(B, C);
  if (!RA || !RB)
    return false;

  RA = RA->getBaseRegion();
  RB = RB->getBaseRegion();
  if (!RA || !RB)
    return false;

  return RA == RB;
}

// Check if the then-branch of the if-stmt contains a return that returns ENOMEM.
bool SAGenTestChecker::thenBranchReturnsENOMEM(const IfStmt *IfS,
                                               CheckerContext &C) const {
  if (!IfS)
    return false;

  const Stmt *ThenS = IfS->getThen();
  if (!ThenS)
    return false;

  const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
  if (!RS)
    return false;

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return false;

  // Accept either ENOMEM or -ENOMEM textually.
  if (ExprHasName(RetE, "ENOMEM", C))
    return true;

  return false;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  // Find the containing IfStmt.
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  // Ensure we are analyzing this If's condition (avoid nested conditions confusion).
  const Expr *IfCond = dyn_cast<Expr>(IfS->getCond());
  if (!IfCond)
    return;

  const Expr *CheckedPtrExpr = nullptr;
  if (!isNullCheckTrueBranch(IfCond, CheckedPtrExpr, C))
    return;

  // Only consider cases where the true-branch returns ENOMEM (to reduce false positives).
  if (!thenBranchReturnsENOMEM(IfS, C))
    return;

  // Find the immediate previous statement in the same compound statement.
  const CompoundStmt *ParentCS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
  if (!ParentCS)
    return;

  const Stmt *Prev = nullptr;
  const Stmt *Target = IfS;
  for (const Stmt *Child : ParentCS->body()) {
    if (Child == Target)
      break;
    Prev = Child;
  }

  if (!Prev)
    return;

  // Extract LHS assigned by allocator call from the previous statement.
  const Expr *LHSExpr = nullptr;
  const CallExpr *AllocCall = nullptr;
  if (!getAssignedLHSFromStmt(Prev, LHSExpr, AllocCall, C))
    return;

  // If the checked expression is the same region as allocated LHS, it's fine.
  if (regionEqual(CheckedPtrExpr, LHSExpr, C))
    return;

  // Otherwise, report: allocated into X but checked Y.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Mismatched NULL check after allocation", N);

  // Highlight the allocation target and the checked expression.
  if (AllocCall)
    R->addRange(AllocCall->getSourceRange());
  if (LHSExpr)
    R->addRange(LHSExpr->getSourceRange());
  if (CheckedPtrExpr)
    R->addRange(CheckedPtrExpr->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects checking a different pointer than the one just allocated (missed NULL check).",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
