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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded strcpy into fixed-size buffer", "Buffer Overflow")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static bool extractFixedArraySizeFromMemberExpr(const MemberExpr *ME, llvm::APInt &OutSize, std::string &FieldName);
      static bool getFixedArraySizeFromDestArg(const Expr *DestE, CheckerContext &C, llvm::APInt &OutSize, std::string &FieldName);
      static bool getStringLiteralSizeOfExpr(const Expr *E, CheckerContext &C, llvm::APInt &OutSize);
      static bool getFixedArraySizeFromExpr(const Expr *E, CheckerContext &C, llvm::APInt &OutSize);
};

bool SAGenTestChecker::extractFixedArraySizeFromMemberExpr(const MemberExpr *ME,
                                                           llvm::APInt &OutSize,
                                                           std::string &FieldName) {
  if (!ME)
    return false;
  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast_or_null<FieldDecl>(VD);
  if (!FD)
    return false;

  QualType FT = FD->getType();
  const Type *Ty = FT.getTypePtrOrNull();
  if (!Ty)
    return false;

  const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(Ty);
  if (!CAT)
    return false;

  OutSize = CAT->getSize();
  FieldName = FD->getNameAsString();
  return true;
}

bool SAGenTestChecker::getFixedArraySizeFromDestArg(const Expr *DestE,
                                                    CheckerContext &C,
                                                    llvm::APInt &OutSize,
                                                    std::string &FieldName) {
  if (!DestE)
    return false;

  // Try to find DeclRefExpr in children
  if (const auto *DREChild = findSpecificTypeInChildren<DeclRefExpr>(DestE)) {
    if (getArraySizeFromExpr(OutSize, DREChild)) {
      FieldName.clear();
      return true;
    }
  }

  // Try direct DeclRefExpr after ignoring implicit
  if (const auto *DRE = dyn_cast<DeclRefExpr>(DestE->IgnoreImpCasts())) {
    if (getArraySizeFromExpr(OutSize, DRE)) {
      FieldName.clear();
      return true;
    }
  }

  // Try to find MemberExpr in children
  if (const auto *MEChild = findSpecificTypeInChildren<MemberExpr>(DestE)) {
    if (extractFixedArraySizeFromMemberExpr(MEChild, OutSize, FieldName))
      return true;
  }

  // Try direct MemberExpr
  if (const auto *MEDirect = dyn_cast<MemberExpr>(DestE->IgnoreImpCasts())) {
    if (extractFixedArraySizeFromMemberExpr(MEDirect, OutSize, FieldName))
      return true;
  }

  return false;
}

bool SAGenTestChecker::getStringLiteralSizeOfExpr(const Expr *E, CheckerContext &C,
                                                  llvm::APInt &OutSize) {
  if (!E)
    return false;
  const Expr *EI = E->IgnoreImpCasts();
  return getStringSize(OutSize, EI);
}

bool SAGenTestChecker::getFixedArraySizeFromExpr(const Expr *E, CheckerContext &C,
                                                 llvm::APInt &OutSize) {
  if (!E)
    return false;

  // DeclRefExpr path
  if (const auto *DREChild = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    if (getArraySizeFromExpr(OutSize, DREChild))
      return true;
  }
  if (const auto *DREDirect = dyn_cast<DeclRefExpr>(E->IgnoreImpCasts())) {
    if (getArraySizeFromExpr(OutSize, DREDirect))
      return true;
  }

  // MemberExpr path
  std::string Dummy;
  if (const auto *MEChild = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (extractFixedArraySizeFromMemberExpr(MEChild, OutSize, Dummy))
      return true;
  }
  if (const auto *MEDirect = dyn_cast<MemberExpr>(E->IgnoreImpCasts())) {
    if (extractFixedArraySizeFromMemberExpr(MEDirect, OutSize, Dummy))
      return true;
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Confirm it's a call to strcpy
  if (!ExprHasName(OriginExpr, "strcpy", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *DestE = Call.getArgExpr(0);
  const Expr *SrcE  = Call.getArgExpr(1);
  if (!DestE || !SrcE)
    return;

  // Determine destination fixed array size
  llvm::APInt DestSize;
  std::string FieldName;
  if (!getFixedArraySizeFromDestArg(DestE, C, DestSize, FieldName))
    return; // Only warn when destination is a known fixed-size array

  // Determine source length/upper bound if possible
  llvm::APInt SrcStrLen;
  bool SrcIsStringLiteral = getStringLiteralSizeOfExpr(SrcE, C, SrcStrLen);

  // If source is a string literal, we can precisely tell overflow:
  // Need DestSize > SrcLen to fit null terminator. If SrcLen >= DestSize, definite overflow.
  if (SrcIsStringLiteral) {
    if (SrcStrLen.uge(DestSize)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      std::string Msg = "strcpy overflows fixed-size buffer";
      if (!FieldName.empty()) {
        Msg += " into field '";
        Msg += FieldName;
        Msg += "'";
      }

      auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
      R->addRange(Call.getSourceRange());
      C.emitReport(std::move(R));
    }
    return; // If literal fits, it's safe; no report.
  }

  // Try to detect if source is also a fixed-size array (capacity bound).
  llvm::APInt SrcArrSize;
  if (getFixedArraySizeFromExpr(SrcE, C, SrcArrSize)) {
    // If source capacity is >= dest capacity, strcpy may overflow.
    // We still treat it as a potential overflow.
    if (SrcArrSize.uge(DestSize)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      std::string Msg = "Unbounded strcpy into fixed-size buffer may overflow";
      if (!FieldName.empty()) {
        Msg += " (field '";
        Msg += FieldName;
        Msg += "')";
      }

      auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
      R->addRange(Call.getSourceRange());
      C.emitReport(std::move(R));
    }
    return; // If source capacity < dest capacity, likely okay; no report.
  }

  // Unknown source length; strcpy is unbounded -> potential overflow.
  {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    std::string Msg = "Unbounded strcpy into fixed-size buffer may overflow";
    if (!FieldName.empty()) {
      Msg += " (field '";
      Msg += FieldName;
      Msg += "')";
    }

    auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    R->addRange(Call.getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded strcpy into fixed-size buffers (e.g., struct fields) that may overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
