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

// No custom program states are needed for this pattern.

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded string copy to fixed-size buffer", "Security")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      bool isStrcpyCall(const CallEvent &Call, CheckerContext &C) const;

      // Extract fixed array size and element type from a struct/union field used as expression E.
      bool getFixedArraySizeFromStructField(const Expr *E, CheckerContext &C,
                                            llvm::APInt &Size, QualType &ElemTy) const;

      // Returns true if the element type is char/signed char/unsigned char (after canonicalization).
      bool isCharLikeType(QualType T) const;

      // Try to get a constant array size from an arbitrary expression (decl ref or member expr).
      bool getConstArraySizeFromExpr(const Expr *E, CheckerContext &C, llvm::APInt &Size) const;

      void reportStrcpyOverflow(const CallEvent &Call, CheckerContext &C, bool Definite) const;
};

bool SAGenTestChecker::isStrcpyCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  // Use the provided helper to match the callee name.
  return ExprHasName(OriginExpr, "strcpy", C);
}

bool SAGenTestChecker::isCharLikeType(QualType T) const {
  QualType CT = T.getCanonicalType().getUnqualifiedType();
  return CT->isCharType() || CT->isSignedCharType() || CT->isUnsignedCharType();
}

bool SAGenTestChecker::getFixedArraySizeFromStructField(const Expr *E, CheckerContext &C,
                                                        llvm::APInt &Size, QualType &ElemTy) const {
  if (!E)
    return false;

  // Find the underlying MemberExpr (e.g., di.name) in the expression.
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(E);
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast<FieldDecl>(VD);
  if (!FD)
    return false;

  QualType FT = FD->getType();
  const ConstantArrayType *CAT = C.getASTContext().getAsConstantArrayType(FT);
  if (!CAT)
    return false;

  ElemTy = CAT->getElementType();
  Size = CAT->getSize();
  return true;
}

bool SAGenTestChecker::getConstArraySizeFromExpr(const Expr *E, CheckerContext &C, llvm::APInt &Size) const {
  if (!E)
    return false;

  // First try the helper for DeclRefExpr-based arrays.
  if (getArraySizeFromExpr(Size, E))
    return true;

  // If that fails, try to see if it's a struct/union field with constant array type.
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(E);
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast<FieldDecl>(VD);
  if (!FD)
    return false;

  const ConstantArrayType *CAT = C.getASTContext().getAsConstantArrayType(FD->getType());
  if (!CAT)
    return false;

  Size = CAT->getSize();
  return true;
}

void SAGenTestChecker::reportStrcpyOverflow(const CallEvent &Call, CheckerContext &C, bool Definite) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  const char *Msg = Definite
                        ? "strcpy overflows fixed-size field"
                        : "strcpy into fixed-size struct field may overflow; use strscpy(..., sizeof(dest))";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isStrcpyCall(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *DestArg = Call.getArgExpr(0);
  const Expr *SrcArg  = Call.getArgExpr(1);
  if (!DestArg || !SrcArg)
    return;

  // Destination must be a struct/union field that is a constant-size char array.
  llvm::APInt DestSize;
  QualType DestElemTy;
  if (!getFixedArraySizeFromStructField(DestArg, C, DestSize, DestElemTy))
    return;

  if (!isCharLikeType(DestElemTy))
    return;

  // Analyze source.
  // 1) If it's a string literal, check if it fits (including NUL terminator).
  llvm::APInt StrLen;
  if (getStringSize(StrLen, SrcArg)) {
    uint64_t Required = StrLen.getZExtValue() + 1; // include NUL
    uint64_t DstCap = DestSize.getZExtValue();
    if (Required > DstCap) {
      // Definite overflow
      reportStrcpyOverflow(Call, C, /*Definite=*/true);
    }
    return; // Literal fits or overflow already reported.
  }

  // 2) If source has a known constant array bound and it's larger than dest, report possible overflow.
  llvm::APInt SrcSize;
  if (getConstArraySizeFromExpr(SrcArg, C, SrcSize)) {
    uint64_t SrcCap = SrcSize.getZExtValue();
    uint64_t DstCap = DestSize.getZExtValue();
    if (SrcCap > DstCap) {
      // Likely overflow because src capacity exceeds dest capacity.
      reportStrcpyOverflow(Call, C, /*Definite=*/false);
    }
    return;
  }

  // 3) Otherwise, unknown/unbounded source copied via strcpy into fixed-size field: report possible overflow.
  reportStrcpyOverflow(Call, C, /*Definite=*/false);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects strcpy into fixed-size struct field; suggest using strscpy with sizeof(dest)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
