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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Overflow-prone allocation size (use kcalloc)", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Return true if Call is one of the array-aware allocators that should be ignored.
      bool isArrayAwareAllocator(const CallEvent &Call, CheckerContext &C) const;

      // If Call is a target allocator that takes a single total size parameter,
      // set Idx to the index of that size argument and return true.
      bool getAllocatorSizeArgIndex(const CallEvent &Call, unsigned &Idx, CheckerContext &C) const;

      // Returns true if expression subtree contains a sizeof(...) (UnaryExprOrTypeTraitExpr of kind SizeOf).
      static bool exprContainsSizeof(const Expr *E);

      // Report helper
      void reportMulPattern(const BinaryOperator *Mul, CheckerContext &C) const;
};

bool SAGenTestChecker::isArrayAwareAllocator(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Orig = Call.getOriginExpr();
  if (!Orig)
    return false;

  // Ignore calls that already use overflow-safe array helpers.
  static const char *ArrayAware[] = {
      "kcalloc",
      "kvcalloc",
      "kmalloc_array",
      "kvmalloc_array",
      "devm_kcalloc"
  };

  for (const char *Name : ArrayAware) {
    if (ExprHasName(Orig, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::getAllocatorSizeArgIndex(const CallEvent &Call, unsigned &Idx, CheckerContext &C) const {
  const Expr *Orig = Call.getOriginExpr();
  if (!Orig)
    return false;

  // Order matters where names can be substrings of others. Keep more specific first.
  struct Entry { const char *Name; unsigned SizeIdx; };
  static const Entry Targets[] = {
      {"devm_kzalloc", 1},
      {"devm_kmalloc", 1},
      {"kvzalloc", 0},
      {"kvmalloc", 0},
      {"kzalloc", 0},
      {"kmalloc", 0},
      {"vzalloc", 0},
  };

  for (const auto &E : Targets) {
    if (ExprHasName(Orig, E.Name, C)) {
      Idx = E.SizeIdx;
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::exprContainsSizeof(const Expr *E) {
  if (!E) return false;
  const Stmt *S = dyn_cast<Stmt>(E);
  if (!S) return false;

  const auto *UETT = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(S);
  if (!UETT) return false;
  return UETT->getKind() == UETT_SizeOf;
}

void SAGenTestChecker::reportMulPattern(const BinaryOperator *Mul, CheckerContext &C) const {
  if (!Mul) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use kcalloc(count, size, ...) instead of count*sizeof in allocation to avoid integer overflow",
      N);
  R->addRange(Mul->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Ignore non-interesting calls first.
  if (isArrayAwareAllocator(Call, C))
    return;

  unsigned SizeIdx = 0;
  if (!getAllocatorSizeArgIndex(Call, SizeIdx, C))
    return;

  if (Call.getNumArgs() <= SizeIdx)
    return;

  const Expr *SizeE = Call.getArgExpr(SizeIdx);
  if (!SizeE)
    return;

  // Suppress safe helpers used inside size expression.
  if (ExprHasName(SizeE, "array_size", C) ||
      ExprHasName(SizeE, "struct_size", C) ||
      ExprHasName(SizeE, "flex_array_size", C))
    return;

  SizeE = SizeE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(SizeE);
  if (!BO || BO->getOpcode() != BO_Mul)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  // Look for sizeof(...) on either side to match "count * sizeof(T)" or "sizeof(T) * count"
  bool HasSizeof = exprContainsSizeof(LHS) || exprContainsSizeof(RHS);
  if (!HasSizeof)
    return;

  reportMulPattern(BO, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects kmalloc/kzalloc-style allocations that multiply count by sizeof; suggest kcalloc to avoid overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
