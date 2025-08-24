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
#include "clang/AST/Type.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state required.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unbounded strcpy into fixed-size buffer",
                       "Buffer overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  static bool isStrcpyLike(const CallEvent &Call, CheckerContext &C);
  static bool getFixedArrayBoundFromArg(const Expr *Arg, CheckerContext &C,
                                        llvm::APInt &Bound, QualType &ElemTy);
  static bool getExactStringLiteralLength(const Expr *Arg, CheckerContext &C,
                                          llvm::APInt &Len);
  static bool isCharLike(QualType T);
};

bool SAGenTestChecker::isStrcpyLike(const CallEvent &Call,
                                    CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  if (!ExprHasName(Origin, "strcpy", C))
    return false;

  // Prefer exact identifier match when available.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    if (ID->getName() != "strcpy")
      return false;
  }
  return true;
}

bool SAGenTestChecker::isCharLike(QualType T) {
  T = T.getCanonicalType();
  if (const auto *BTy = dyn_cast<BuiltinType>(T.getTypePtr())) {
    switch (BTy->getKind()) {
    case BuiltinType::Char_S:
    case BuiltinType::Char_U:
    case BuiltinType::SChar:
    case BuiltinType::UChar:
      return true;
    default:
      return false;
    }
  }
  return false;
}

bool SAGenTestChecker::getFixedArrayBoundFromArg(const Expr *Arg,
                                                 CheckerContext &C,
                                                 llvm::APInt &Bound,
                                                 QualType &ElemTy) {
  if (!Arg)
    return false;

  const Expr *E = Arg->IgnoreParens();

  // We expect an ArrayToPointerDecay when passing arrays to functions.
  if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
    if (ICE->getCastKind() == CK_ArrayToPointerDecay) {
      const Expr *Sub = ICE->getSubExpr();
      if (!Sub)
        return false;
      QualType QT = Sub->getType();
      if (const ConstantArrayType *CAT =
              C.getASTContext().getAsConstantArrayType(QT)) {
        Bound = CAT->getSize();
        ElemTy = CAT->getElementType();
        return true;
      }
    }
  }

  // Fallback: directly check if the (possibly already-decayed) expr has array type.
  E = E->IgnoreParenImpCasts();
  QualType QT = E->getType();
  if (const ConstantArrayType *CAT =
          C.getASTContext().getAsConstantArrayType(QT)) {
    Bound = CAT->getSize();
    ElemTy = CAT->getElementType();
    return true;
  }

  return false;
}

bool SAGenTestChecker::getExactStringLiteralLength(const Expr *Arg,
                                                   CheckerContext &C,
                                                   llvm::APInt &Len) {
  // Utility returns length excluding the terminating NUL.
  return getStringSize(Len, Arg);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isStrcpyLike(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *Dst = Call.getArgExpr(0);
  const Expr *Src = Call.getArgExpr(1);
  if (!Dst || !Src)
    return;

  // Resolve destination fixed-size bound and its element type.
  llvm::APInt DstBound; // number of elements
  QualType ElemTy;
  if (!getFixedArrayBoundFromArg(Dst, C, DstBound, ElemTy))
    return;

  // Only warn for char-like arrays (strcpy semantics).
  if (!isCharLike(ElemTy))
    return;

  // If source is a string literal, we can be precise: need Len+1 bytes incl. NUL.
  llvm::APInt SrcLen;
  if (getExactStringLiteralLength(Src, C, SrcLen)) {
    // Required elements (bytes) = SrcLen + 1 (for NUL).
    llvm::APInt Required = SrcLen + 1;
    if (Required.ugt(DstBound)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "strcpy overflows fixed-size buffer; use strscpy(dst, src, "
               "sizeof(dst))",
          N);
      R->addRange(Dst->getSourceRange());
      C.emitReport(std::move(R));
    }
    return; // Literal fits -> no warning.
  }

  // Non-literal source: strcpy is unbounded, destination is fixed-size.
  {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Unbounded strcpy into fixed-size buffer may overflow; use "
             "strscpy(dst, src, sizeof(dst))",
        N);
    R->addRange(Dst->getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded strcpy into fixed-size buffers and suggests strscpy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
