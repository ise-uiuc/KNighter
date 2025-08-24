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
#include "clang/Lex/Lexer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state required.

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Wrong NULL check after allocation", "Memory Management")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      const Expr *getCheckedPtrExprRaw(const Stmt *Condition, CheckerContext &C) const;
      bool isNullExpr(const Expr *E, CheckerContext &C) const;
      bool isKernelAllocator(const CallExpr *CE, CheckerContext &C) const;
      bool returnsENOMEM(const Stmt *S, CheckerContext &C) const;
      StringRef getExprText(const Expr *E, CheckerContext &C) const;
};

static const CompoundStmt *getEnclosingCompound(const Stmt *S, CheckerContext &C) {
  return findSpecificTypeInParents<CompoundStmt>(S, C);
}

static const IfStmt *getEnclosingIf(const Stmt *S, CheckerContext &C) {
  return findSpecificTypeInParents<IfStmt>(S, C);
}

StringRef SAGenTestChecker::getExprText(const Expr *E, CheckerContext &C) const {
  if (!E)
    return StringRef();
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  return Lexer::getSourceText(Range, SM, LangOpts);
}

bool SAGenTestChecker::isNullExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  return E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
}

bool SAGenTestChecker::isKernelAllocator(const CallExpr *CE, CheckerContext &C) const {
  if (!CE)
    return false;
  // Use source-text based matching for robustness in the absence of direct callee.
  const Expr *E = CE;
  return ExprHasName(E, "kzalloc", C) ||
         ExprHasName(E, "kmalloc", C) ||
         ExprHasName(E, "kcalloc", C) ||
         ExprHasName(E, "kvzalloc", C) ||
         ExprHasName(E, "vzalloc", C) ||
         ExprHasName(E, "devm_kzalloc", C);
}

bool SAGenTestChecker::returnsENOMEM(const Stmt *S, CheckerContext &C) const {
  if (!S)
    return false;

  // Find a ReturnStmt inside S (only one is needed to confirm).
  const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(S);
  if (!RS)
    return false;

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return false;

  // If the return expression mentions ENOMEM, accept.
  if (ExprHasName(RetE, "ENOMEM", C))
    return true;

  // If it is a constant negative integer (e.g., -12), accept.
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, RetE, C)) {
    if (Val.isSigned() ? Val.isNegative() : Val == 0) {
      // If unsigned, can't be negative; otherwise check negativity.
      if (Val.isSigned() && Val.isNegative())
        return true;
    }
  }
  return false;
}

const Expr *SAGenTestChecker::getCheckedPtrExprRaw(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return nullptr;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return nullptr;

  // Analyze the structure while keeping access to raw sub-expressions
  const Expr *Stripped = CondE->IgnoreParenImpCasts();

  // if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(Stripped)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *InnerRaw = UO->getSubExpr(); // Raw subexpr for region extraction
      if (InnerRaw && InnerRaw->getType()->isPointerType())
        return InnerRaw;
    }
  }

  // if (ptr == NULL) or if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(Stripped)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHSRaw = BO->getLHS();
      const Expr *RHSRaw = BO->getRHS();
      if (!LHSRaw || !RHSRaw)
        return nullptr;

      const Expr *LHS = LHSRaw->IgnoreParenImpCasts();
      const Expr *RHS = RHSRaw->IgnoreParenImpCasts();

      bool LHSIsNull = isNullExpr(LHS, C);
      bool RHSIsNull = isNullExpr(RHS, C);

      if (LHSIsNull && !RHSIsNull && RHSRaw->getType()->isPointerType())
        return RHSRaw;
      if (RHSIsNull && !LHSIsNull && LHSRaw->getType()->isPointerType())
        return LHSRaw;
    }
  }

  // if (ptr)
  if (Stripped->getType()->isPointerType())
    return CondE; // raw condition expr

  return nullptr;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Step 3.1: Extract the pointer expression being NULL-checked.
  const Expr *CheckedPtrExpr = getCheckedPtrExprRaw(Condition, C);
  if (!CheckedPtrExpr)
    return;

  // Step 3.2: Find enclosing IfStmt and previous statement in the same CompoundStmt.
  const IfStmt *IfS = getEnclosingIf(Condition, C);
  if (!IfS)
    return;

  const CompoundStmt *CS = getEnclosingCompound(IfS, C);
  if (!CS)
    return;

  const Stmt *PrevS = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (Child == IfS)
      break;
    PrevS = Child;
  }
  if (!PrevS)
    return;

  // Step 3.3: Check if previous statement is an assignment from an allocator call.
  const BinaryOperator *Assign = dyn_cast<BinaryOperator>(PrevS);
  if (!Assign || Assign->getOpcode() != BO_Assign)
    return;

  const Expr *LHSRaw = Assign->getLHS();
  const Expr *RHSRaw = Assign->getRHS();
  if (!LHSRaw || !RHSRaw)
    return;

  const CallExpr *AllocCE = dyn_cast<CallExpr>(RHSRaw->IgnoreParenImpCasts());
  if (!AllocCE)
    return;
  if (!isKernelAllocator(AllocCE, C))
    return;

  // Step 3.4: Compare allocated target and checked pointer.
  const MemRegion *AllocReg = getMemRegionFromExpr(LHSRaw, C);
  const MemRegion *CheckReg = getMemRegionFromExpr(CheckedPtrExpr, C);
  if (AllocReg)
    AllocReg = AllocReg->getBaseRegion();
  if (CheckReg)
    CheckReg = CheckReg->getBaseRegion();

  bool SameRegion = (AllocReg && CheckReg && AllocReg == CheckReg);

  // If regions are equal, it's fine.
  if (SameRegion)
    return;

  // Optional heuristic: if both are member expressions but their base objects differ, be conservative and bail out.
  const Expr *LHSNoCasts = LHSRaw->IgnoreParenImpCasts();
  const Expr *ChkNoCasts = CheckedPtrExpr->IgnoreParenImpCasts();
  if (const auto *LME = dyn_cast<MemberExpr>(LHSNoCasts)) {
    if (const auto *RME = dyn_cast<MemberExpr>(ChkNoCasts)) {
      const Expr *LBase = LME->getBase();
      const Expr *RBase = RME->getBase();
      if (LBase && RBase) {
        const MemRegion *LBReg = getMemRegionFromExpr(LBase, C);
        const MemRegion *RBReg = getMemRegionFromExpr(RBase, C);
        if (LBReg) LBReg = LBReg->getBaseRegion();
        if (RBReg) RBReg = RBReg->getBaseRegion();
        if (LBReg && RBReg && LBReg != RBReg) {
          // Different base objects - likely unrelated, avoid reporting.
          return;
        }
      }
    }
  }

  // Fallback text equality check to avoid false positives if regions are unavailable.
  if (!SameRegion) {
    StringRef LHSText = getExprText(LHSRaw, C);
    StringRef ChkText = getExprText(CheckedPtrExpr, C);
    if (!LHSText.empty() && !ChkText.empty() && LHSText == ChkText) {
      // Same text implies same pointer; do not report.
      return;
    }
  }

  // Step 3.5: Heuristic: ensure this is an OOM check site (returning -ENOMEM)
  const Stmt *ThenS = IfS->getThen();
  if (!returnsENOMEM(ThenS, C))
    return;

  // Step 3.6: Report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Wrong pointer checked after allocation; should check the allocated pointer", N);

  // Highlight the condition and the allocation call site
  R->addRange(Condition->getSourceRange());
  R->addRange(AllocCE->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects checking the wrong pointer for NULL immediately after allocation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
