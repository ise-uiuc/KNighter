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

// No custom program state needed.

namespace {

static const Expr *getUnderlyingArrayExpr(const Expr *E) {
  if (!E)
    return nullptr;

  // Prefer to get the subexpression before array-to-pointer decay.
  if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
    if (ICE->getCastKind() == CK_ArrayToPointerDecay) {
      return ICE->getSubExpr()->IgnoreParenImpCasts();
    }
  }
  return E->IgnoreParenImpCasts();
}

static bool getFixedCharArraySize(const Expr *E, CheckerContext &C,
                                  llvm::APInt &OutSize) {
  if (!E)
    return false;

  QualType QT = E->getType();
  const ConstantArrayType *CAT = C.getASTContext().getAsConstantArrayType(QT);
  if (!CAT)
    return false;

  QualType ElemTy = CAT->getElementType();
  if (!ElemTy->isAnyCharacterType())
    return false;

  OutSize = CAT->getSize();
  return true;
}

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded string copy", "Security")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      void reportStrcpyOverflow(const CallEvent &Call, CheckerContext &C,
                                StringRef Msg) const;
};

void SAGenTestChecker::reportStrcpyOverflow(const CallEvent &Call,
                                            CheckerContext &C,
                                            StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Identify strcpy
  bool IsStrcpy = false;
  const Expr *OriginExpr = Call.getOriginExpr();
  if (OriginExpr && ExprHasName(OriginExpr, "strcpy", C))
    IsStrcpy = true;
  if (const IdentifierInfo *II = Call.getCalleeIdentifier())
    IsStrcpy = IsStrcpy || II->getName() == "strcpy";

  if (!IsStrcpy)
    return;

  if (Call.getNumArgs() < 2)
    return;

  // Get destination argument and determine if it's a fixed-size char array.
  const Expr *DestArg = Call.getArgExpr(0);
  const Expr *DestArrExpr = getUnderlyingArrayExpr(DestArg);
  llvm::APInt DestSize;
  if (!getFixedCharArraySize(DestArrExpr, C, DestSize))
    return; // Only warn when destination capacity is known and char-like.

  uint64_t DestCap = DestSize.getZExtValue();

  // Analyze source argument.
  const Expr *SrcArg = Call.getArgExpr(1);
  llvm::APInt SrcLiteralLen;
  if (getStringSize(SrcLiteralLen, SrcArg)) {
    // StringLiteral length excludes the null terminator.
    uint64_t SrcLen = SrcLiteralLen.getZExtValue();
    // strcpy writes SrcLen + 1 bytes including the terminator.
    if (SrcLen >= DestCap) {
      reportStrcpyOverflow(Call, C,
        "strcpy to fixed-size buffer overflows; use strscpy(dest, src, sizeof(dest))");
    }
    // Else: Source literal fits; no warning.
    return;
  }

  // Non-literal or unknown source length: warn as potentially overflowing.
  reportStrcpyOverflow(Call, C,
    "strcpy to fixed-size buffer may overflow; use strscpy(dest, src, sizeof(dest))");
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects strcpy into fixed-size buffers; suggest strscpy with sizeof(dest)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
