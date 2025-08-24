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
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"
#include <limits>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Allocator size multiplication may overflow", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static bool isFunctionNamed(const CallEvent &Call, CheckerContext &C, StringRef Name);
      static bool isArrayAllocator(const CallEvent &Call, CheckerContext &C);
      static bool isScalarAllocator(const CallEvent &Call, CheckerContext &C);
      static const BinaryOperator *findMulInSizeExpr(const Expr *E);
      static const UnaryExprOrTypeTraitExpr *findSizeofInExpr(const Expr *E);
      static bool getElementSizeFromSizeof(const UnaryExprOrTypeTraitExpr *UE, const ASTContext &ACtx, uint64_t &Out);
      static bool tryGetSymbolForExpr(const Expr *E, CheckerContext &C, SymbolRef &OutSym);
      static bool isProvablySafeCount(SymbolRef CountSym, uint64_t ElemSize, CheckerContext &C);
};

bool SAGenTestChecker::isFunctionNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

bool SAGenTestChecker::isArrayAllocator(const CallEvent &Call, CheckerContext &C) {
  // Known safe array allocators
  static const char *Names[] = {
      "kcalloc", "kmalloc_array", "kvcalloc", "devm_kcalloc"
  };
  for (auto *N : Names)
    if (isFunctionNamed(Call, C, N))
      return true;
  return false;
}

bool SAGenTestChecker::isScalarAllocator(const CallEvent &Call, CheckerContext &C) {
  // Scalar allocators with single size parameter
  static const char *Names[] = {
      "kmalloc", "kzalloc", "kvzalloc", "kmalloc_node", "kzalloc_node",
      "devm_kmalloc", "devm_kzalloc"
  };
  for (auto *N : Names)
    if (isFunctionNamed(Call, C, N))
      return true;
  return false;
}

const BinaryOperator *SAGenTestChecker::findMulInSizeExpr(const Expr *E) {
  if (!E)
    return nullptr;
  // Find a BinaryOperator somewhere under E
  if (const auto *BO = findSpecificTypeInChildren<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Mul)
      return BO;
  }
  return nullptr;
}

const UnaryExprOrTypeTraitExpr *SAGenTestChecker::findSizeofInExpr(const Expr *E) {
  if (!E)
    return nullptr;
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(E)) {
    if (UE->getKind() == UETT_SizeOf)
      return UE;
  }
  return nullptr;
}

bool SAGenTestChecker::getElementSizeFromSizeof(const UnaryExprOrTypeTraitExpr *UE,
                                                const ASTContext &ACtx, uint64_t &Out) {
  if (!UE)
    return false;

  // Try to evaluate sizeof expression directly first
  llvm::APSInt EvalRes;
  Expr::EvalResult ER;
  if (UE->EvaluateAsInt(ER, ACtx)) {
    EvalRes = ER.Val.getInt();
    Out = EvalRes.getZExtValue();
    return true;
  }

  // Fallback: compute from type if available
  QualType QT;
  if (UE->isArgumentType())
    QT = UE->getArgumentType();
  else if (const Expr *ArgE = UE->getArgumentExpr())
    QT = ArgE->getType();

  if (QT.isNull())
    return false;

  CharUnits CU = ACtx.getTypeSizeInChars(QT);
  Out = static_cast<uint64_t>(CU.getQuantity());
  return true;
}

bool SAGenTestChecker::tryGetSymbolForExpr(const Expr *E, CheckerContext &C, SymbolRef &OutSym) {
  if (!E)
    return false;
  ProgramStateRef State = C.getState();
  SVal V = State->getSVal(E, C.getLocationContext());
  if (SymbolRef S = V.getAsSymbol()) {
    OutSym = S;
    return true;
  }
  return false;
}

bool SAGenTestChecker::isProvablySafeCount(SymbolRef CountSym, uint64_t ElemSize, CheckerContext &C) {
  if (!CountSym || ElemSize == 0)
    return false;

  const llvm::APSInt *MaxVAPS = inferSymbolMaxVal(CountSym, C);
  if (!MaxVAPS)
    return false;

  // Compute the maximum size_t value based on target size.
  const ASTContext &ACtx = C.getASTContext();
  unsigned SizeTBits = ACtx.getTypeSize(ACtx.getSizeType());
  uint64_t MaxSizeT;
  if (SizeTBits >= 64)
    MaxSizeT = std::numeric_limits<uint64_t>::max();
  else
    MaxSizeT = (SizeTBits == 0) ? 0ULL : ((1ULL << SizeTBits) - 1ULL);

  if (ElemSize == 0)
    return false;

  uint64_t LimitCount = MaxSizeT / ElemSize;

  // Compare max bound of CountSym with limit.
  uint64_t SymMax = MaxVAPS->getZExtValue();
  return SymMax <= LimitCount;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Ignore safe array allocators outright.
  if (isArrayAllocator(Call, C))
    return;

  // Only handle scalar allocators from our target set.
  if (!isScalarAllocator(Call, C))
    return;

  if (Call.getNumArgs() == 0)
    return;

  const Expr *SizeE = Call.getArgExpr(0);
  if (!SizeE)
    return;
  SizeE = SizeE->IgnoreParenImpCasts();

  // Suppress if compile-time constant size (cannot overflow dynamically).
  llvm::APSInt CEval;
  if (EvaluateExprToInt(CEval, SizeE, C))
    return;

  // Look for a multiplication in the size expression.
  const BinaryOperator *Mul = findMulInSizeExpr(SizeE);
  if (!Mul)
    return;

  // Verify the mul is a sizeof(...) * count pattern.
  const Expr *LHS = Mul->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = Mul->getRHS()->IgnoreParenImpCasts();

  const UnaryExprOrTypeTraitExpr *SizeofOnLHS = findSizeofInExpr(LHS);
  const UnaryExprOrTypeTraitExpr *SizeofOnRHS = findSizeofInExpr(RHS);

  // Fallback text search if AST pattern isn't found.
  if (!SizeofOnLHS && ExprHasName(LHS, "sizeof", C))
    SizeofOnLHS = findSizeofInExpr(LHS);
  if (!SizeofOnRHS && ExprHasName(RHS, "sizeof", C))
    SizeofOnRHS = findSizeofInExpr(RHS);

  if (!SizeofOnLHS && !SizeofOnRHS)
    return; // Not a sizeof(...) * count shape.

  // Optional suppression via symbolic bounds:
  // If exactly one side has sizeof, try to get a symbol for the other side
  // and check its maximal value against SIZE_MAX / elem_size.
  const Expr *CountExpr = nullptr;
  const UnaryExprOrTypeTraitExpr *SizeofExpr = nullptr;
  if (SizeofOnLHS && !SizeofOnRHS) {
    SizeofExpr = SizeofOnLHS;
    CountExpr = RHS;
  } else if (!SizeofOnLHS && SizeofOnRHS) {
    SizeofExpr = SizeofOnRHS;
    CountExpr = LHS;
  }

  bool Suppress = false;
  if (CountExpr && SizeofExpr) {
    uint64_t ElemSize = 0;
    if (getElementSizeFromSizeof(SizeofExpr, C.getASTContext(), ElemSize) && ElemSize > 0) {
      SymbolRef CountSym = nullptr;
      if (tryGetSymbolForExpr(CountExpr, C, CountSym)) {
        if (isProvablySafeCount(CountSym, ElemSize, C))
          Suppress = true;
      }
    }
  }

  if (Suppress)
    return;

  // Report warning: multiplication-based size in scalar allocator -> suggest array allocators.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Size uses sizeof(...) * count in kmalloc/kzalloc; use kcalloc/kmalloc_array to avoid overflow",
      N);

  // Highlight the size argument.
  if (const Expr *Arg0 = Call.getArgExpr(0))
    R->addRange(Arg0->getSourceRange());

  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects kmalloc/kzalloc with sizeof(...) * count; suggest kcalloc/kmalloc_array to avoid overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
