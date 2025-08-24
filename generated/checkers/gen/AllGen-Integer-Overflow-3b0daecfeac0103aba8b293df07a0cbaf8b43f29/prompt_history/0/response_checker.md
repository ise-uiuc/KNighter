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
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No program state customization needed.
namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Allocator integer overflow risk", "Memory")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Helper to check if the call name matches using ExprHasName or callee identifier.
      static bool isCallNamed(const CallEvent &Call, CheckerContext &C, StringRef Name);
      // Is allocator of interest (kmalloc/kzalloc and their _node/__ variants), not kcalloc/kvcalloc.
      static bool isAllocatorOfInterest(const CallEvent &Call, CheckerContext &C);
      // Returns true if expression text uses overflow-safe helpers.
      static bool isUsingOverflowSafeHelper(const Expr *E, CheckerContext &C);
      // Returns true if E is a multiplication that directly involves a sizeof.
      static bool isRawSizeofMultiply(const Expr *E);
};

bool SAGenTestChecker::isCallNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  const Expr *Origin = Call.getOriginExpr();
  if (Origin && ExprHasName(Origin, Name, C))
    return true;
  if (const IdentifierInfo *II = Call.getCalleeIdentifier())
    return II->getName() == Name;
  return false;
}

bool SAGenTestChecker::isAllocatorOfInterest(const CallEvent &Call, CheckerContext &C) {
  // Exclude safe array allocators
  if (isCallNamed(Call, C, "kcalloc") || isCallNamed(Call, C, "kvcalloc"))
    return false;

  // Target allocators that take a size argument as first parameter
  if (isCallNamed(Call, C, "kmalloc") ||
      isCallNamed(Call, C, "__kmalloc") ||
      isCallNamed(Call, C, "kmalloc_node") ||
      isCallNamed(Call, C, "kzalloc") ||
      isCallNamed(Call, C, "kzalloc_node")) {
    return true;
  }
  return false;
}

bool SAGenTestChecker::isUsingOverflowSafeHelper(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "array_size", C) ||
         ExprHasName(E, "struct_size", C) ||
         ExprHasName(E, "flex_array_size", C);
}

bool SAGenTestChecker::isRawSizeofMultiply(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO) return false;
  if (BO->getOpcode() != BO_Mul) return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  auto HasSizeof = [](const Expr *X) -> bool {
    if (!X) return false;
    if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(X)) {
      return U->getKind() == UETT_SizeOf;
    }
    return false;
  };

  return HasSizeof(L) || HasSizeof(R);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAllocatorOfInterest(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;

  SizeArg = SizeArg->IgnoreParenImpCasts();

  // Suppress when using overflow-safe helpers
  if (isUsingOverflowSafeHelper(SizeArg, C))
    return;

  // Only warn when the size arg is a raw multiply including sizeof(...)
  if (!isRawSizeofMultiply(SizeArg))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use kcalloc(n, sizeof(T), ...) instead of kmalloc/kzalloc with sizeof(T) * n; unchecked multiplication may overflow",
      N);

  R->addRange(SizeArg->getSourceRange());
  if (const Stmt *S = Call.getOriginExpr())
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect kmalloc/kzalloc with sizeof(T) * n; suggest kcalloc to avoid overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
