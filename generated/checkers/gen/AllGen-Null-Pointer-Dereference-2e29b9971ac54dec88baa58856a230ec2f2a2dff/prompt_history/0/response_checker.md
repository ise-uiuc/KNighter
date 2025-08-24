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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are needed.

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Wrong NULL check after allocation", "Logic error")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Extract the pointer expression being NULL-checked in a condition.
      const Expr *extractNullCheckedPtr(const Expr *Cond, CheckerContext &C) const;
      // Determine if a CallExpr calls a known allocator (e.g., kzalloc, kmalloc, etc.).
      bool isKnownAllocatorCall(const CallExpr *CE, CheckerContext &C) const;
      // Unwrap wrappers to reach the core expression (e.g., ExprWithCleanups).
      const Expr *unwrapToCoreExpr(const Stmt *S) const;
};

const Expr *SAGenTestChecker::unwrapToCoreExpr(const Stmt *S) const {
  const Stmt *Cur = S;
  while (true) {
    if (const auto *EWC = dyn_cast<ExprWithCleanups>(Cur)) {
      Cur = EWC->getSubExpr();
      continue;
    }
    if (const auto *FE = dyn_cast<FullExpr>(Cur)) {
      Cur = FE->getSubExpr();
      continue;
    }
    break;
  }
  return dyn_cast<Expr>(Cur);
}

bool SAGenTestChecker::isKnownAllocatorCall(const CallExpr *CE, CheckerContext &C) const {
  if (!CE)
    return false;
  const Expr *CalleeE = CE->getCallee();
  if (!CalleeE)
    return false;

  // Use source-text-based name matching for robustness as suggested.
  static const char *Allocators[] = {
    "kzalloc", "kmalloc", "kcalloc", "kvzalloc", "vzalloc", "kvmalloc",
    "devm_kzalloc", "devm_kmalloc", "devm_kcalloc"
  };
  for (const char *Name : Allocators) {
    if (ExprHasName(CalleeE, Name, C))
      return true;
  }
  return false;
}

const Expr *SAGenTestChecker::extractNullCheckedPtr(const Expr *Cond, CheckerContext &C) const {
  if (!Cond)
    return nullptr;

  const ASTContext &ACtx = C.getASTContext();
  const Expr *E = Cond->IgnoreParenCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      if (SubE && SubE->getType()->isPointerType())
        return SubE;
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && RHS && RHS->getType()->isPointerType())
        return RHS;
      if (RHSIsNull && LHS && LHS->getType()->isPointerType())
        return LHS;
    }
  }
  return nullptr;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  // Find the enclosing IfStmt for this condition.
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Extract the pointer being NULL-checked in the condition.
  const Expr *CheckedPtrExpr = extractNullCheckedPtr(CondE, C);
  if (!CheckedPtrExpr)
    return;

  // Find the enclosing compound statement to get the previous sibling statement.
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
  if (!CS)
    return;

  // Locate IfS within CS and get the previous statement.
  const Stmt *PrevStmt = nullptr;
  for (auto I = CS->body_begin(), E = CS->body_end(); I != E; ++I) {
    if (*I == IfS) {
      if (I == CS->body_begin())
        return; // No previous statement.
      PrevStmt = *(std::prev(I));
      break;
    }
  }
  if (!PrevStmt)
    return;

  // Unwrap to core expression.
  const Expr *PrevCoreE = unwrapToCoreExpr(PrevStmt);
  if (!PrevCoreE)
    return;

  // Ensure it's an assignment of the form LHS = allocatorCall(...);
  const auto *BO = dyn_cast<BinaryOperator>(PrevCoreE);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS(); // Do not IgnoreImplicit before region extraction.
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // RHS should be an allocator call.
  const CallExpr *AllocCE = dyn_cast<CallExpr>(RHS->IgnoreParenCasts());
  if (!isKnownAllocatorCall(AllocCE, C))
    return;

  // Both sides should be pointer-typed to be relevant.
  if (!LHS->getType()->isPointerType())
    return;
  if (!CheckedPtrExpr->getType()->isPointerType())
    return;

  // Get memory regions for both the allocated pointer (LHS) and the checked pointer.
  const MemRegion *AllocMRRaw = getMemRegionFromExpr(LHS, C);
  const MemRegion *ChkMRRaw = getMemRegionFromExpr(CheckedPtrExpr, C);
  if (!AllocMRRaw || !ChkMRRaw)
    return;

  const MemRegion *AllocMRBase = AllocMRRaw->getBaseRegion();
  const MemRegion *ChkMRBase = ChkMRRaw->getBaseRegion();
  if (!AllocMRBase || !ChkMRBase)
    return;

  // We consider it a mismatch if:
  //  - The underlying root object is the same (same base region),
  //  - But the specific regions differ (e.g., different fields).
  if (AllocMRBase == ChkMRBase && AllocMRRaw != ChkMRRaw) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Wrong pointer checked after allocation", N);
    R->addRange(IfS->getCond()->getSourceRange());
    R->addRange(BO->getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects checking a different pointer than the one just allocated (wrong NULL check)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
