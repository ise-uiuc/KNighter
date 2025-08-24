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
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states required.

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded strcpy into fixed-size buffer", "Memory Safety")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static const Expr *unwrapArrayDecay(const Expr *E);
      static bool getConstantArraySizeFromExpr(const Expr *E, llvm::APInt &Size);
      static bool isStrcpyOrBuiltin(const CallEvent &Call, CheckerContext &C);
      static bool isStrcatOrBuiltin(const CallEvent &Call, CheckerContext &C);
      static void report(CheckerContext &C, const CallEvent &Call, StringRef Msg);
};

// Unwrap Array-to-pointer decay from ImplicitCastExpr or UnaryOperator (defensive)
const Expr *SAGEN_NOEXCEPT unwrapArrayDecayImpl(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  // Handle ImplicitCastExpr CK_ArrayToPointerDecay
  if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
    if (ICE->getCastKind() == CK_ArrayToPointerDecay) {
      E = ICE->getSubExpr()->IgnoreParenImpCasts();
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_ArrayToPointerDecay) {
      E = UO->getSubExpr()->IgnoreParenImpCasts();
    }
  }
  return E;
}
const Expr *SAGenTestChecker::unwrapArrayDecay(const Expr *E) {
  return unwrapArrayDecayImpl(E);
}

// Try to get constant array size from expressions like:
// - DeclRefExpr to array variable
// - MemberExpr to struct/union field of ConstantArrayType
bool SAGenTestChecker::getConstantArraySizeFromExpr(const Expr *E, llvm::APInt &Size) {
  if (!E) return false;

  // First try helper for DeclRefExpr directly
  if (getArraySizeFromExpr(Size, E))
    return true;

  // Remove decays and casts
  E = unwrapArrayDecay(E);
  if (!E) return false;

  // Try again after unwrap for DeclRefExpr
  if (getArraySizeFromExpr(Size, E))
    return true;

  // Handle MemberExpr to a field of ConstantArrayType
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    const ValueDecl *VD = ME->getMemberDecl();
    if (const auto *FD = dyn_cast<FieldDecl>(VD)) {
      QualType FT = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr())) {
        Size = CAT->getSize();
        return true;
      }
    }
  }

  // Also handle a DeclRefExpr to a variable of ConstantArrayType (fallback)
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType T = VD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(T.getTypePtr())) {
        Size = CAT->getSize();
        return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::isStrcpyOrBuiltin(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Use source text matcher helper for robustness (macros, builtins)
  if (ExprHasName(Origin, "strcpy", C))
    return true;
  if (ExprHasName(Origin, "__builtin_strcpy", C))
    return true;
  return false;
}

bool SAGenTestChecker::isStrcatOrBuiltin(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  if (ExprHasName(Origin, "strcat", C))
    return true;
  if (ExprHasName(Origin, "__builtin_strcat", C))
    return true;
  return false;
}

void SAGenTestChecker::report(CheckerContext &C, const CallEvent &Call, StringRef Msg) {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  bool IsStrcpy = isStrcpyOrBuiltin(Call, C);
  bool IsStrcat = isStrcatOrBuiltin(Call, C);
  if (!IsStrcpy && !IsStrcat)
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *Dest = Call.getArgExpr(0);
  const Expr *Src  = Call.getArgExpr(1);
  if (!Dest || !Src)
    return;

  // Destination must be a fixed-size array to avoid FPs.
  llvm::APInt DestSize(32, 0);
  bool DestKnown = getConstantArraySizeFromExpr(Dest, DestSize);
  if (!DestKnown)
    return;

  // Determine source length if possible
  llvm::APInt SrcLitLen(32, 0);
  bool SrcIsLiteral = getStringSize(SrcLitLen, Src);

  llvm::APInt SrcArrSize(32, 0);
  bool SrcIsConstArray = getConstantArraySizeFromExpr(Src, SrcArrSize);

  // Decision logic
  if (IsStrcpy) {
    // strcpy copies literal length + 1 for the null
    if (SrcIsLiteral) {
      llvm::APInt BytesCopied = SrcLitLen + 1; // include null
      if (BytesCopied.ugt(DestSize)) {
        SmallString<128> Msg;
        llvm::raw_svector_ostream OS(Msg);
        OS << "strcpy overflows fixed-size buffer (dest size=" << DestSize
           << ", src literal bytes=" << BytesCopied << ")";
        report(C, Call, OS.str());
        return;
      }
      // literal fits: no warning
      return;
    }

    if (SrcIsConstArray) {
      // If the source array's bound is larger than dest, likely overflow.
      if (SrcArrSize.ugt(DestSize)) {
        SmallString<128> Msg;
        llvm::raw_svector_ostream OS(Msg);
        OS << "strcpy may overflow fixed-size buffer (dest size=" << DestSize
           << ", src bound=" << SrcArrSize << ")";
        report(C, Call, OS.str());
        return;
      }
      // If src bound <= dest bound, avoid warning to control FPs.
      return;
    }

    // Unknown source length, but dest is fixed-size: unbounded copy -> warn.
    {
      SmallString<128> Msg;
      llvm::raw_svector_ostream OS(Msg);
      OS << "Unbounded strcpy into fixed-size buffer; possible overflow (dest size=" << DestSize << ")";
      report(C, Call, OS.str());
      return;
    }
  } else {
    // strcat: also unbounded; conservative handling like strcpy
    if (SrcIsLiteral) {
      llvm::APInt BytesAppended = SrcLitLen; // strcat appends literal without replacing dest's existing content; null terminator also written but hard to account
      // We cannot know current length of dest. Still unbounded into fixed-size buffer.
      SmallString<128> Msg;
      llvm::raw_svector_ostream OS(Msg);
      OS << "Unbounded strcat into fixed-size buffer; possible overflow (dest size=" << DestSize << ")";
      report(C, Call, OS.str());
      return;
    }

    if (SrcIsConstArray) {
      if (SrcArrSize.ugt(DestSize)) {
        SmallString<128> Msg;
        llvm::raw_svector_ostream OS(Msg);
        OS << "strcat may overflow fixed-size buffer (dest size=" << DestSize
           << ", src bound=" << SrcArrSize << ")";
        report(C, Call, OS.str());
        return;
      }
      // Still unbounded due to unknown existing length in dest; warn conservatively.
      SmallString<128> Msg;
      llvm::raw_svector_ostream OS(Msg);
      OS << "Unbounded strcat into fixed-size buffer; possible overflow (dest size=" << DestSize << ")";
      report(C, Call, OS.str());
      return;
    }

    // Unknown source: warn
    {
      SmallString<128> Msg;
      llvm::raw_svector_ostream OS(Msg);
      OS << "Unbounded strcat into fixed-size buffer; possible overflow (dest size=" << DestSize << ")";
      report(C, Call, OS.str());
      return;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded strcpy/strcat into fixed-size buffers that may overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
