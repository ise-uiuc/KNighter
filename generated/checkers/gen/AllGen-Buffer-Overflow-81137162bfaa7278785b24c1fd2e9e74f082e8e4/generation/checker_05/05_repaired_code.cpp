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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary for this checker.

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded string copy into fixed-size buffer", "Buffer Overflow")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      bool isUnboundedStringCopy(const CallEvent &Call, CheckerContext &C) const;
      bool isCharType(QualType T) const;
      bool getFixedArraySizeFromMemberExpr(const MemberExpr *ME, llvm::APInt &OutSize, QualType &ElemTy) const;
      bool getFixedArraySizeFromDestExpr(const Expr *DestArg, llvm::APInt &OutSize, QualType &ElemTy, CheckerContext &C) const;
};

bool SAGenTestChecker::isUnboundedStringCopy(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Use source-based name matching for robustness.
  if (ExprHasName(Origin, "strcpy", C))
    return true;
  if (ExprHasName(Origin, "stpcpy", C))
    return true;
  if (ExprHasName(Origin, "strcat", C))
    return true;

  // Fallback to callee identifier if available.
  if (const IdentifierInfo *II = Call.getCalleeIdentifier()) {
    StringRef N = II->getName();
    return N == "strcpy" || N == "stpcpy" || N == "strcat";
  }
  return false;
}

bool SAGenTestChecker::isCharType(QualType T) const {
  if (T.isNull())
    return false;
  // Check if the element type is any character type (char, signed char, unsigned char).
  return T->isAnyCharacterType();
}

bool SAGenTestChecker::getFixedArraySizeFromMemberExpr(const MemberExpr *ME, llvm::APInt &OutSize, QualType &ElemTy) const {
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD)
    return false;

  QualType FT = VD->getType();
  const Type *Ty = FT.getTypePtrOrNull();
  if (!Ty)
    return false;

  if (const auto *CAT = dyn_cast<ConstantArrayType>(Ty)) {
    ElemTy = CAT->getElementType();
    OutSize = CAT->getSize();
    return true;
  }
  return false;
}

bool SAGenTestChecker::getFixedArraySizeFromDestExpr(const Expr *DestArg, llvm::APInt &OutSize, QualType &ElemTy, CheckerContext &C) const {
  if (!DestArg)
    return false;

  // Strip implicit casts
  const Expr *E = DestArg->IgnoreImplicit();

  // Try DeclRefExpr path: dest refers directly to an array variable.
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    if (const auto *VarD = dyn_cast_or_null<VarDecl>(VD)) {
      QualType VT = VarD->getType();
      const Type *Ty = VT.getTypePtrOrNull();
      if (!Ty)
        return false;
      if (const auto *CAT = dyn_cast<ConstantArrayType>(Ty)) {
        ElemTy = CAT->getElementType();
        OutSize = CAT->getSize();
        return true;
      }
    }
    // Fallthrough if not a constant array
  }

  // Try MemberExpr path: struct/union fixed-size array field.
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (getFixedArraySizeFromMemberExpr(ME, OutSize, ElemTy))
      return true;
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // 1) Identify unbounded string-copy functions.
  if (!isUnboundedStringCopy(Call, C))
    return;

  // Expect at least 2 arguments (dest, src).
  if (Call.getNumArgs() < 2)
    return;

  // 2) Analyze the destination argument to ensure it is a fixed-size char array.
  const Expr *DestArg = Call.getArgExpr(0);
  llvm::APInt Capacity;
  QualType ElemTy;

  if (!getFixedArraySizeFromDestExpr(DestArg, Capacity, ElemTy, C))
    return;

  if (!isCharType(ElemTy))
    return;

  // 3) Inspect the source argument.
  const Expr *SrcArg = Call.getArgExpr(1);
  llvm::APInt StringSize;

  // If the source is a string literal with a known length:
  if (getStringSize(StringSize, SrcArg)) {
    // StringSize is number of characters excluding the null terminator.
    // For strcpy/stpcpy/strcat, if StringSize >= Capacity, copy can't fit including NUL.
    if (StringSize.uge(Capacity)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unbounded string copy into fixed-size buffer may overflow; use strscpy with sizeof(dest).", N);
      if (const Stmt *S = Call.getOriginExpr())
        R->addRange(S->getSourceRange());
      C.emitReport(std::move(R));
    }
    // If StringSize < Capacity, don't warn: the literal definitely fits.
    return;
  }

  // If not a string literal, we cannot prove safety. Report as potentially overflowing.
  {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Unbounded string copy into fixed-size buffer may overflow; use strscpy with sizeof(dest).", N);
    if (const Stmt *S = Call.getOriginExpr())
      R->addRange(S->getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded string copy into fixed-size buffers (use strscpy with sizeof(dest))",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
