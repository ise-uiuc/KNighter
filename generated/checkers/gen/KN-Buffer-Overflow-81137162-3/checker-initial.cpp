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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No program state customization needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded string copy into fixed-size buffer", "Memory Safety")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helper to check if call is to an unbounded copy API like strcpy
      static bool isUnboundedCopy(const CallEvent &Call, CheckerContext &C);

      // Get constant array size and element type from a destination expression
      static bool getFixedArraySize(const Expr *E, llvm::APInt &OutSize, QualType &ElemTy, CheckerContext &C);

      // Check if element type is a character type (char, signed char, unsigned char)
      static bool isCharType(QualType T);

      // Try to extract constant array info from a QualType
      static bool getConstArrayInfo(QualType QT, llvm::APInt &OutSize, QualType &ElemTy);
};

bool SAGenTestChecker::isUnboundedCopy(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Prefer robust textual matching function provided.
  if (ExprHasName(OriginExpr, "strcpy", C))
    return true;

  return false;
}

bool SAGenTestChecker::getConstArrayInfo(QualType QT, llvm::APInt &OutSize, QualType &ElemTy) {
  if (const auto *CAT = dyn_cast_or_null<ConstantArrayType>(QT.getTypePtr())) {
    OutSize = CAT->getSize();
    ElemTy = CAT->getElementType();
    return true;
  }
  return false;
}

bool SAGenTestChecker::isCharType(QualType T) {
  T = T.getCanonicalType();
  if (T->isAnyCharacterType())
    return true;

  if (const auto *BT = T->getAs<BuiltinType>()) {
    switch (BT->getKind()) {
    case BuiltinType::SChar:
    case BuiltinType::UChar:
    case BuiltinType::Char_S:
    case BuiltinType::Char_U:
    case BuiltinType::Char8:
      return true;
    default:
      break;
    }
  }
  return false;
}

bool SAGenTestChecker::getFixedArraySize(const Expr *E, llvm::APInt &OutSize, QualType &ElemTy, CheckerContext &C) {
  if (!E)
    return false;

  const Expr *Cur = E->IgnoreImpCasts();

  // Handle &arr[0]
  if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
    if (UO->getOpcode() == UO_AddrOf) {
      Cur = UO->getSubExpr()->IgnoreImpCasts();
    }
  }

  // Direct variable reference of an array
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Cur)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return getConstArrayInfo(VD->getType(), OutSize, ElemTy);
    }
  }

  // Struct/union member array like di.name
  if (const auto *ME = dyn_cast<MemberExpr>(Cur)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      return getConstArrayInfo(FD->getType(), OutSize, ElemTy);
    }
  }

  // Array subscript like arr[0] or s.name[0]
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Cur)) {
    const Expr *Base = ASE->getBase()->IgnoreImpCasts();
    const Expr *Idx = ASE->getIdx()->IgnoreImpCasts();

    // Evaluate index, ensure it is 0
    llvm::APSInt IdxVal;
    if (!EvaluateExprToInt(IdxVal, Idx, C))
      return false;
    if (IdxVal != 0)
      return false;

    // Base can be DeclRefExpr or MemberExpr (array)
    if (const auto *BDRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const auto *VD = dyn_cast<VarDecl>(BDRE->getDecl())) {
        return getConstArrayInfo(VD->getType(), OutSize, ElemTy);
      }
    } else if (const auto *BME = dyn_cast<MemberExpr>(Base)) {
      if (const auto *FD = dyn_cast<FieldDecl>(BME->getMemberDecl())) {
        return getConstArrayInfo(FD->getType(), OutSize, ElemTy);
      }
    }
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isUnboundedCopy(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *DestE = Call.getArgExpr(0);
  if (!DestE)
    return;

  llvm::APInt DestSize(64, 0);
  QualType ElemTy;
  if (!getFixedArraySize(DestE, DestSize, ElemTy, C))
    return;

  if (!isCharType(ElemTy))
    return;

  // Optional refinement if source is string literal
  const Expr *SrcE = Call.getArgExpr(1);
  if (!SrcE)
    return;

  llvm::APInt StringLen;
  bool DefiniteOverflow = false;
  if (getStringSize(StringLen, SrcE)) {
    // strcpy copies src length + 1 (for NUL). If StringLen >= DestSize, definite overflow.
    if (StringLen.uge(DestSize))
      DefiniteOverflow = true;
    else
      return; // Clearly safe with literal smaller than dest.
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg;
  if (DefiniteOverflow) {
    unsigned long long D = DestSize.getLimitedValue();
    unsigned long long S = StringLen.getLimitedValue();
    Msg = "strcpy may overflow fixed-size buffer (dest size " + std::to_string(D) +
          ", source literal length " + std::to_string(S) + ")";
  } else {
    Msg = "Unbounded copy into fixed-size buffer; use strscpy(dest, src, sizeof(dest))";
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(DestE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded string copies (e.g., strcpy) into fixed-size buffers; suggests strscpy with sizeof(dest)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
