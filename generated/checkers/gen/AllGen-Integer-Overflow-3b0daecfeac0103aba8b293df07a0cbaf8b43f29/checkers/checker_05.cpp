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
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Integer overflow in allocation size", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Checks if the call is one of the allocation functions we care about.
      bool isTargetAllocCall(const CallEvent &Call, CheckerContext &C) const;

      // Try to get the multiplication BO from the size argument (arg index 0).
      const BinaryOperator *getMulInSizeArg(const CallEvent &Call) const;

      // Whether the expr is a sizeof(...) expression.
      static bool isSizeofExpr(const Expr *E);

      // Try an optional range-based suppression: if CountMax <= MaxSize/ElemSize, skip.
      bool provenNoOverflow(const Expr *CountExpr, const Expr *SizeofExpr, CheckerContext &C) const;

      // Report a diagnostic on risky pattern.
      void reportRisk(const CallEvent &Call, const BinaryOperator *Mul, CheckerContext &C) const;
};

bool SAGenTestChecker::isTargetAllocCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Use ExprHasName for accurate matching.
  // Check common kernel allocators where arg0 is the size:
  static const char *Names[] = {
      "kmalloc", "kzalloc",
      "kmalloc_node", "kzalloc_node",
      "kvmalloc", "kvzalloc"
  };

  for (const char *N : Names) {
    if (ExprHasName(Origin, N, C))
      return true;
  }
  return false;
}

const BinaryOperator *SAGenTestChecker::getMulInSizeArg(const CallEvent &Call) const {
  if (Call.getNumArgs() == 0)
    return nullptr;
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return nullptr;

  Arg0 = Arg0->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Arg0);
  if (!BO)
    return nullptr;

  if (BO->getOpcode() != BO_Mul)
    return nullptr;

  return BO;
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

bool SAGenTestChecker::provenNoOverflow(const Expr *CountExpr, const Expr *SizeofExpr, CheckerContext &C) const {
  if (!CountExpr || !SizeofExpr)
    return false;

  // Get element size from sizeof, should be constant.
  llvm::APSInt ElemSizeAPS;
  if (!EvaluateExprToInt(ElemSizeAPS, SizeofExpr, C))
    return false;

  // sizeof(...) should be positive and non-zero
  uint64_t ElemSize = ElemSizeAPS.getZExtValue();
  if (ElemSize == 0)
    return false;

  // Infer maximum of CountExpr
  ProgramStateRef State = C.getState();
  SVal CountSVal = State->getSVal(CountExpr, C.getLocationContext());
  SymbolRef SymCount = CountSVal.getAsSymbol();
  if (!SymCount)
    return false;

  const llvm::APSInt *CountMax = inferSymbolMaxVal(SymCount, C);
  if (!CountMax)
    return false;

  // Compute Max size_t value, then SafeLimit = floor(max_size_t / ElemSize).
  ASTContext &ACtx = C.getASTContext();
  QualType SizeT = ACtx.getSizeType();
  unsigned BitWidth = ACtx.getTypeSize(SizeT);
  llvm::APInt MaxSizeAP = llvm::APInt::getMaxValue(BitWidth);
  llvm::APInt ElemSizeAP(BitWidth, ElemSize, /*isSigned=*/false);
  // Avoid division by zero (already checked).
  llvm::APInt SafeLimitAP = MaxSizeAP.udiv(ElemSizeAP);

  // Compare CountMax (might have different bitwidth). Convert CountMax to APInt with BitWidth.
  llvm::APInt CountMaxAP = CountMax->getExtValue() >= 0
                               ? llvm::APInt(BitWidth, CountMax->getZExtValue(), false)
                               : llvm::APInt(BitWidth, 0, false); // negative counts don't make sense; ignore as not proven safe

  // If CountMax <= SafeLimit, proven no overflow.
  if (CountMaxAP.ule(SafeLimitAP))
    return true;

  return false;
}

void SAGenTestChecker::reportRisk(const CallEvent &Call, const BinaryOperator *Mul, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Multiplying count and element size in kmalloc/kzalloc may overflow; use kcalloc/kmalloc_array",
      N);
  if (Mul)
    R->addRange(Mul->getSourceRange());
  else if (const Expr *Arg0 = Call.getArgExpr(0))
    R->addRange(Arg0->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isTargetAllocCall(Call, C))
    return;

  const BinaryOperator *Mul = getMulInSizeArg(Call);
  if (!Mul)
    return;

  const Expr *L = Mul->getLHS()->IgnoreParenImpCasts();
  const Expr *R = Mul->getRHS()->IgnoreParenImpCasts();

  // Must have a sizeof on one side.
  bool LIsSizeof = isSizeofExpr(L);
  bool RIsSizeof = isSizeofExpr(R);
  if (!LIsSizeof && !RIsSizeof)
    return;

  // Skip purely constant multiplications to reduce false positives.
  llvm::APSInt ValTmp;
  bool LConst = EvaluateExprToInt(ValTmp, L, C);
  bool RConst = EvaluateExprToInt(ValTmp, R, C);
  if (LConst && RConst)
    return;

  // Optional suppression: if we can prove max(count) * elem <= SIZE_MAX, skip.
  const Expr *CountExpr = LIsSizeof ? R : L;
  const Expr *SizeofExpr = LIsSizeof ? L : R;
  if (provenNoOverflow(CountExpr, SizeofExpr, C))
    return;

  reportRisk(Call, Mul, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects risky allocation size calculations using sizeof(T) * n in kmalloc/kzalloc; suggest kcalloc/kmalloc_array",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
