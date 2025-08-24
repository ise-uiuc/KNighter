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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Open-coded size multiplication may overflow",
                       "Integer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Return true if this is a target function, and set SizeIdx to the size arg.
  bool isTargetFunction(const CallEvent &Call, CheckerContext &C,
                        unsigned &SizeIdx) const;

  // Return true if E is a sizeof(...) expression.
  static bool isSizeofExpr(const Expr *E);

  // Report a concise diagnostic on SizeE.
  void report(const Expr *SizeE, CheckerContext &C) const;
};

// Determine if the call is to copy_from_user or copy_to_user and set size index.
bool SAGenTestChecker::isTargetFunction(const CallEvent &Call,
                                        CheckerContext &C,
                                        unsigned &SizeIdx) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Use text-based matching as suggested.
  if (ExprHasName(OE, "copy_from_user", C) || ExprHasName(OE, "copy_to_user", C)) {
    // Signature: (dst, src, n) -> size index = 2
    if (Call.getNumArgs() > 2) {
      SizeIdx = 2;
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!E)
    return false;
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    return U->getKind() == UETT_SizeOf;
  }
  return false;
}

void SAGenTestChecker::report(const Expr *SizeE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Size is computed as sizeof(x) * count; use array_size() to avoid overflow", N);
  if (SizeE)
    R->addRange(SizeE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SizeIdx = 0;
  if (!isTargetFunction(Call, C, SizeIdx))
    return;

  if (SizeIdx >= Call.getNumArgs())
    return;

  const Expr *SizeE = Call.getArgExpr(SizeIdx);
  if (!SizeE)
    return;

  // If already using safe helpers, skip.
  if (ExprHasName(SizeE, "array_size", C) || ExprHasName(SizeE, "struct_size", C))
    return;

  const Expr *E = SizeE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  bool LIsSizeof = isSizeofExpr(L);
  bool RIsSizeof = isSizeofExpr(R);

  // We care about exactly one side being sizeof(...)
  if (LIsSizeof == RIsSizeof)
    return;

  const Expr *CountExpr = LIsSizeof ? R : L;
  if (!CountExpr)
    return;

  // If count is a compile-time constant, skip (low risk).
  llvm::APSInt Dummy;
  if (EvaluateExprToInt(Dummy, CountExpr, C))
    return;

  // Otherwise, this matches the open-coded sizeof * count pattern.
  report(SizeE, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects open-coded sizeof(x) * count in size arguments; suggests array_size()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
