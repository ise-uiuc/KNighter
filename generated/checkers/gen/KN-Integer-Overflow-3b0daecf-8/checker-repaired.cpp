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
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unchecked size multiplication in allocation", "Memory")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      bool isSingleSizeAllocCall(const CallEvent &Call, CheckerContext &C,
                                 unsigned &SizeIndex, StringRef &NameOut) const;

      bool isSafeCAllocCall(const CallEvent &Call, CheckerContext &C) const;

      const BinaryOperator *getMultiplicationInExpr(const Expr *E) const;

      const UnaryExprOrTypeTraitExpr *getSizeOfInExpr(const Expr *E) const;

      bool tryProveNoOverflow(const BinaryOperator *MulBO,
                              const UnaryExprOrTypeTraitExpr *SizeOfE,
                              CheckerContext &C) const;

      void report(const Expr *Arg, StringRef CalleeName, CheckerContext &C) const;
};

bool SAGenTestChecker::isSafeCAllocCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Safe calloc-like helpers
  if (ExprHasName(Origin, "kcalloc", C) ||
      ExprHasName(Origin, "kvcalloc", C))
    return true;
  return false;
}

bool SAGenTestChecker::isSingleSizeAllocCall(const CallEvent &Call, CheckerContext &C,
                                             unsigned &SizeIndex, StringRef &NameOut) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Allocation APIs that take a single "total size" argument at index 0.
  static const char *Names[] = {
      "kmalloc", "kzalloc", "__kmalloc", "kmalloc_node", "kzalloc_node",
      "vmalloc", "vzalloc", "__vmalloc",
      "kvmalloc", "kvzalloc", "kvmalloc_node"
  };

  for (const char *N : Names) {
    if (ExprHasName(Origin, N, C)) {
      NameOut = N;
      SizeIndex = 0;
      return true;
    }
  }
  return false;
}

const BinaryOperator *SAGenTestChecker::getMultiplicationInExpr(const Expr *E) const {
  if (!E)
    return nullptr;
  const Expr *EE = E->IgnoreParenImpCasts();
  // Look downwards for a BinaryOperator
  if (const auto *FoundBO = findSpecificTypeInChildren<BinaryOperator>(EE))
    if (FoundBO->getOpcode() == BO_Mul)
      return FoundBO;
  // If the expression itself is a BO *
  if (const auto *BO = dyn_cast<BinaryOperator>(EE))
    if (BO->getOpcode() == BO_Mul)
      return BO;
  return nullptr;
}

const UnaryExprOrTypeTraitExpr *SAGenTestChecker::getSizeOfInExpr(const Expr *E) const {
  if (!E)
    return nullptr;
  const Expr *EE = E->IgnoreParenImpCasts();
  if (const auto *UETT = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(EE)) {
    if (UETT->getKind() == UETT_SizeOf)
      return UETT;
  }
  if (const auto *SelfUETT = dyn_cast<UnaryExprOrTypeTraitExpr>(EE)) {
    if (SelfUETT->getKind() == UETT_SizeOf)
      return SelfUETT;
  }
  return nullptr;
}

bool SAGenTestChecker::tryProveNoOverflow(const BinaryOperator *MulBO,
                                          const UnaryExprOrTypeTraitExpr *SizeOfE,
                                          CheckerContext &C) const {
  if (!MulBO || !SizeOfE)
    return false;

  // Evaluate sizeof(...) to integer
  llvm::APSInt ElemSizeAPS;
  if (!EvaluateExprToInt(ElemSizeAPS, SizeOfE, C))
    return false;

  // Identify the "count" side of the multiplication
  const Expr *LHS = MulBO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = MulBO->getRHS()->IgnoreParenImpCasts();

  const Expr *CountExpr = nullptr;
  // If LHS is sizeof, count is RHS
  if (isa<UnaryExprOrTypeTraitExpr>(LHS) &&
      cast<UnaryExprOrTypeTraitExpr>(LHS)->getKind() == UETT_SizeOf) {
    CountExpr = RHS;
  } else if (isa<UnaryExprOrTypeTraitExpr>(RHS) &&
             cast<UnaryExprOrTypeTraitExpr>(RHS)->getKind() == UETT_SizeOf) {
    CountExpr = LHS;
  } else {
    // Could be nested expressions; fall back to the one that's not sizeof if any
    // but if neither side is a direct sizeof, we can't reliably proceed.
    return false;
  }

  // If the count expression is a constant, then the whole product should be constant,
  // which would have been filtered earlier. So if it's constant, we treat as safe.
  llvm::APSInt CountConst;
  if (EvaluateExprToInt(CountConst, CountExpr, C))
    return true;

  // Get symbolic maximum of count
  ProgramStateRef State = C.getState();
  SVal CountVal = State->getSVal(CountExpr, C.getLocationContext());
  SymbolRef CountSym = CountVal.getAsSymbol();
  if (!CountSym)
    return false;

  const llvm::APSInt *MaxCount = inferSymbolMaxVal(CountSym, C);
  if (!MaxCount)
    return false;

  ASTContext &ACtx = C.getASTContext();
  unsigned SizeBits = ACtx.getTypeSize(ACtx.getSizeType());
  unsigned WideBits = SizeBits * 2;

  llvm::APInt ElemSizeNarrow = ElemSizeAPS.getLimitedValue() == 0
                                   ? llvm::APInt(SizeBits, 0)
                                   : ElemSizeAPS.extOrTrunc(SizeBits).zextOrTrunc(SizeBits);
  if (ElemSizeNarrow.getBitWidth() != SizeBits)
    ElemSizeNarrow = ElemSizeNarrow.zextOrTrunc(SizeBits);

  llvm::APInt MaxCountNarrow = MaxCount->extOrTrunc(SizeBits);
  if (MaxCountNarrow.getBitWidth() != SizeBits)
    MaxCountNarrow = MaxCountNarrow.zextOrTrunc(SizeBits);

  llvm::APInt ElemSizeWide = ElemSizeNarrow.zext(WideBits);
  llvm::APInt MaxCountWide = MaxCountNarrow.zext(WideBits);

  llvm::APInt ProductWide = MaxCountWide * ElemSizeWide;

  llvm::APInt MaxSizeNarrow = llvm::APInt::getMaxValue(SizeBits);
  llvm::APInt MaxSizeWide = MaxSizeNarrow.zext(WideBits);

  // If product under maximum possible count still fits in size_t, it's safe.
  if (ProductWide.ule(MaxSizeWide))
    return true;

  return false;
}

void SAGenTestChecker::report(const Expr *Arg, StringRef CalleeName, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "Unchecked size multiplication in ";
  Msg += CalleeName;
  Msg += "; use kcalloc/kvcalloc (or array_size/struct_size) to avoid overflow";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (Arg)
    R->addRange(Arg->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Do not warn for safe calloc-like helpers.
  if (isSafeCAllocCall(Call, C))
    return;

  unsigned SizeIdx = 0;
  StringRef CalleeName;
  if (!isSingleSizeAllocCall(Call, C, SizeIdx, CalleeName))
    return;

  if (Call.getNumArgs() <= SizeIdx)
    return;

  const Expr *SizeArgE = Call.getArgExpr(SizeIdx);
  if (!SizeArgE)
    return;

  // If the whole size expression is a constant, skip (compiler already folded it).
  llvm::APSInt WholeConst;
  if (EvaluateExprToInt(WholeConst, SizeArgE, C))
    return;

  // We are interested in expressions like sizeof(T) * N
  const BinaryOperator *MulBO = getMultiplicationInExpr(SizeArgE);
  if (!MulBO)
    return;

  const UnaryExprOrTypeTraitExpr *SizeOfE = getSizeOfInExpr(SizeArgE);
  if (!SizeOfE || SizeOfE->getKind() != UETT_SizeOf)
    return;

  // Try to prove safe using a simple max bound check; if provably safe, skip.
  if (tryProveNoOverflow(MulBO, SizeOfE, C))
    return;

  // Otherwise, report a warning.
  report(SizeArgE, CalleeName, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked size multiplication in single-size allocation calls; suggest kcalloc/kvcalloc",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
