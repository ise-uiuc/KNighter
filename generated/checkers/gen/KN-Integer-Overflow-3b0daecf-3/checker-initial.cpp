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
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states required for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Potential overflow in kmalloc/kzalloc size", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      bool isKernelAlloc(const CallEvent &Call, CheckerContext &C) const;
      bool isMulOfSizeofAndCount(const Expr *E,
                                 const BinaryOperator *&Mul,
                                 const Expr *&SizeOfExpr,
                                 const Expr *&CountExpr) const;
      bool evalToInt(llvm::APSInt &Res, const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::isKernelAlloc(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  if (ExprHasName(Origin, "kmalloc", C))
    return true;
  if (ExprHasName(Origin, "kzalloc", C))
    return true;

  return false;
}

bool SAGenTestChecker::evalToInt(llvm::APSInt &Res, const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  return EvaluateExprToInt(Res, E, C);
}

// Try to recognize: <sizeof(...)> * <count> (possibly wrapped in casts/parens)
bool SAGenTestChecker::isMulOfSizeofAndCount(const Expr *E,
                                             const BinaryOperator *&Mul,
                                             const Expr *&SizeOfExpr,
                                             const Expr *&CountExpr) const {
  Mul = nullptr;
  SizeOfExpr = nullptr;
  CountExpr = nullptr;

  if (!E)
    return false;

  const Expr *Norm = E->IgnoreParenImpCasts();
  Mul = dyn_cast<BinaryOperator>(Norm);
  if (!Mul) {
    // Fallback: search within children if wrapped further
    Mul = findSpecificTypeInChildren<BinaryOperator>(E);
  }
  if (!Mul)
    return false;

  if (Mul->getOpcode() != BO_Mul)
    return false;

  const Expr *L = Mul->getLHS()->IgnoreParenImpCasts();
  const Expr *R = Mul->getRHS()->IgnoreParenImpCasts();

  const auto *UL = dyn_cast<UnaryExprOrTypeTraitExpr>(L);
  const auto *UR = dyn_cast<UnaryExprOrTypeTraitExpr>(R);

  if (UL && UL->getKind() == UETT_SizeOf) {
    SizeOfExpr = L;
    CountExpr = R;
    return true;
  }
  if (UR && UR->getKind() == UETT_SizeOf) {
    SizeOfExpr = R;
    CountExpr = L;
    return true;
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isKernelAlloc(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *SizeArg = Call.getArgExpr(0);
  if (!SizeArg)
    return;

  // Step B/C: look for sizeof(..) * count pattern in the size argument
  const BinaryOperator *Mul = nullptr;
  const Expr *SizeOfExpr = nullptr;
  const Expr *CountExpr = nullptr;
  if (!isMulOfSizeofAndCount(SizeArg, Mul, SizeOfExpr, CountExpr))
    return;

  // Step D: If total size is compile-time constant, don't warn.
  llvm::APSInt TotalConst;
  if (evalToInt(TotalConst, SizeArg, C))
    return;

  // Evaluate sizeof side (usually constant). If it fails, we keep going conservatively.
  llvm::APSInt SizeOfConst;
  bool HasSizeOfConst = evalToInt(SizeOfConst, SizeOfExpr, C);

  // If count side is compile-time constant, consider low risk and don't warn.
  llvm::APSInt CountConst;
  if (evalToInt(CountConst, CountExpr, C))
    return;

  // Step E: Try to prove that the multiplication cannot overflow via max bound
  // Otherwise, report.
  bool ProvenSafe = false;

  if (HasSizeOfConst) {
    // Try to infer maximal value of count symbolically.
    ProgramStateRef State = C.getState();
    SVal CountSV = State->getSVal(CountExpr, C.getLocationContext());
    SymbolRef Sym = CountSV.getAsSymbol();

    if (Sym) {
      if (const llvm::APSInt *MaxCount = inferSymbolMaxVal(Sym, C)) {
        // Compute if MaxCount * SizeOfConst fits into the bitwidth of the size argument type.
        unsigned Width = C.getASTContext().getTypeSize(SizeArg->getType());
        if (Width == 0)
          Width = std::max<unsigned>(64, SizeOfConst.getBitWidth());

        // Prepare APInts as unsigned
        llvm::APInt MaxVal = llvm::APInt::getMaxValue(Width);

        // Zero-extend/truncate operands to Width
        llvm::APInt SizeAP(Width, SizeOfConst.getZExtValue());
        llvm::APInt CountAP(Width, MaxCount->getZExtValue());

        if (SizeAP == 0) {
          // Zero size means no overflow and no risk (but also nonsense alloc); treat as safe to avoid false positive.
          ProvenSafe = true;
        } else {
          // If MaxCount <= MaxVal / Size then product cannot overflow.
          llvm::APInt UB = MaxVal.udiv(SizeAP);
          if (CountAP.ule(UB))
            ProvenSafe = true;
        }
      }
    }
  }

  if (ProvenSafe)
    return;

  // Report: potentially overflowing kmalloc/kzalloc size computation
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use kcalloc(n, size) to avoid overflow in kmalloc/kzalloc size computation", N);
  R->addRange(SizeArg->getSourceRange());
  if (CountExpr)
    R->addRange(CountExpr->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect kmalloc/kzalloc with sizeof(...) * count size that may overflow; suggest kcalloc",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
