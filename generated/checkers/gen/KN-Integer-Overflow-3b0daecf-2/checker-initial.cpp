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
#include "clang/AST/ExprCXX.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Array allocation with kmalloc/kzalloc may overflow", "Memory")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Returns true if E represents a multiplication that contains a sizeof(...)
      // term and another "count" term. Outputs CountExpr and SizeofExpr on success.
      static bool isMulOfSizeof(const Expr *E, const Expr *&CountExpr, const Expr *&SizeofExpr);

      // Helper to check if an expression is a sizeof.
      static bool isSizeOfExpr(const Expr *E);

      // Helper to match allocator names using ExprHasName.
      static bool isTargetAllocator(const CallEvent &Call, CheckerContext &C);
};

bool SAGenTestChecker::isSizeOfExpr(const Expr *E) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!E) return false;
  if (const auto *UETT = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    return UETT->getKind() == UETT_SizeOf;
  }
  return false;
}

bool SAGenTestChecker::isMulOfSizeof(const Expr *E, const Expr *&CountExpr, const Expr *&SizeofExpr) {
  CountExpr = nullptr;
  SizeofExpr = nullptr;
  if (!E) return false;

  const Expr *EE = E->IgnoreParenImpCasts();

  auto TryFromBO = [&](const BinaryOperator *BO) -> bool {
    if (!BO || BO->getOpcode() != BO_Mul)
      return false;

    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

    if (isSizeOfExpr(L)) {
      SizeofExpr = L;
      CountExpr = R;
      return true;
    }
    if (isSizeOfExpr(R)) {
      SizeofExpr = R;
      CountExpr = L;
      return true;
    }
    return false;
  };

  if (const auto *TopBO = dyn_cast<BinaryOperator>(EE)) {
    if (TryFromBO(TopBO))
      return true;
  }

  // Look deeper in the expression tree for a multiplication node.
  if (const auto *InnerBO = findSpecificTypeInChildren<BinaryOperator>(EE)) {
    return TryFromBO(InnerBO);
  }

  return false;
}

bool SAGenTestChecker::isTargetAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Target functions:
  // kmalloc(size, gfp)
  // kzalloc(size, gfp)
  // __kmalloc(size, gfp)
  // kmalloc_node(size, gfp, node)
  // kzalloc_node(size, gfp, node)
  static const char *Targets[] = {
      "kmalloc", "kzalloc", "__kmalloc", "kmalloc_node", "kzalloc_node"
  };

  for (const char *Name : Targets) {
    if (ExprHasName(Origin, Name, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isTargetAllocator(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *SizeArgE = Call.getArgExpr(0);
  if (!SizeArgE)
    return;

  const Expr *CountExpr = nullptr;
  const Expr *SizeofExpr = nullptr;
  if (!isMulOfSizeof(SizeArgE, CountExpr, SizeofExpr))
    return;

  // Suppress if the count is a compile-time constant to reduce noise.
  llvm::APSInt EvalRes;
  if (CountExpr && EvaluateExprToInt(EvalRes, CountExpr, C)) {
    return; // Constant count - skip warning.
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "kmalloc/kzalloc size uses count * element size; use kcalloc(count, elem_size, ...) to avoid overflow",
      N);

  R->addRange(SizeArgE->getSourceRange());
  if (CountExpr)
    R->addRange(CountExpr->getSourceRange());
  if (SizeofExpr)
    R->addRange(SizeofExpr->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects kmalloc/kzalloc array allocations using count*sizeof that may overflow; suggests kcalloc",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
