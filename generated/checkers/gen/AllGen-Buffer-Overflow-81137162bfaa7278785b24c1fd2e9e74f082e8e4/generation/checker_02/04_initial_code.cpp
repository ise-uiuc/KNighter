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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer Overflow", "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  static bool isStrcpyLike(const CallEvent &Call, CheckerContext &C);
  static bool getConstArrayBound(const Expr *E, llvm::APInt &Bound, const ASTContext &ACtx);
  static bool getStringLiteralLen(const Expr *E, llvm::APInt &LenOut);
  void report(const CallEvent &Call, CheckerContext &C, bool Definite,
              uint64_t DstSize) const;
};

// Determine if a call is to strcpy or its builtin variant.
bool SAGenTestChecker::isStrcpyLike(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Prefer text-based matching as advised.
  if (ExprHasName(Origin, "strcpy", C))
    return true;
  if (ExprHasName(Origin, "__builtin_strcpy", C))
    return true;

  // Fallback to identifier check (exact names only).
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef N = ID->getName();
    if (N == "strcpy" || N == "__builtin_strcpy")
      return true;
  }
  return false;
}

// Try to get a compile-time constant array bound from an expression
bool SAGenTestChecker::getConstArrayBound(const Expr *E, llvm::APInt &Bound,
                                          const ASTContext &ACtx) {
  if (!E)
    return false;

  const Expr *PE = E->IgnoreParenImpCasts();

  QualType QT;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(PE)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      QT = VD->getType();
  } else if (const auto *ME = dyn_cast<MemberExpr>(PE)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
      QT = FD->getType();
  } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(PE)) {
    // Handle cases like dest[0], take the base expression type.
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *BDRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const auto *VD = dyn_cast<VarDecl>(BDRE->getDecl()))
        QT = VD->getType();
    } else if (const auto *BME = dyn_cast<MemberExpr>(Base)) {
      if (const auto *FD = dyn_cast<FieldDecl>(BME->getMemberDecl()))
        QT = FD->getType();
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(PE)) {
    // Handle &arr[0] or similar. Try to peel further.
    if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref) {
      return getConstArrayBound(UO->getSubExpr(), Bound, ACtx);
    }
  }

  if (QT.isNull())
    return false;

  QT = QT.getCanonicalType();
  if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
    Bound = CAT->getSize();
    return true;
  }
  return false;
}

// Get string literal length (without the terminating null).
bool SAGenTestChecker::getStringLiteralLen(const Expr *E, llvm::APInt &LenOut) {
  return getStringSize(LenOut, E);
}

void SAGenTestChecker::report(const CallEvent &Call, CheckerContext &C,
                              bool Definite, uint64_t DstSize) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  llvm::SmallString<128> Msg;
  if (Definite) {
    Msg = "strcpy overflows fixed-size buffer";
  } else {
    Msg = "strcpy into fixed-size buffer may overflow; use strscpy(..., sizeof(dest))";
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.c_str(), N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isStrcpyLike(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *DstE = Call.getArgExpr(0);
  const Expr *SrcE = Call.getArgExpr(1);
  if (!DstE || !SrcE)
    return;

  const ASTContext &ACtx = C.getASTContext();
  llvm::APInt DstBound;
  if (!getConstArrayBound(DstE, DstBound, ACtx)) {
    // Only warn when destination is a compile-time fixed-size array.
    return;
  }

  // If source is a string literal, we can determine definiteness.
  llvm::APInt SrcLen;
  if (getStringLiteralLen(SrcE, SrcLen)) {
    uint64_t Needs = SrcLen.getZExtValue() + 1; // include terminating null
    uint64_t DstSz = DstBound.getZExtValue();
    if (Needs > DstSz) {
      report(Call, C, /*Definite=*/true, DstSz);
    }
    // else: definitely fits, no warning.
    return;
  }

  // If source is a constant array, compare capacities as a heuristic.
  llvm::APInt SrcBound;
  if (getConstArrayBound(SrcE, SrcBound, ACtx)) {
    uint64_t SrcCap = SrcBound.getZExtValue();
    uint64_t DstSz = DstBound.getZExtValue();
    if (SrcCap > DstSz) {
      report(Call, C, /*Definite=*/false, DstSz);
    }
    // Else: source capacity <= dest, likely safe.
    return;
  }

  // Unknown source length; strcpy is unbounded -> potential overflow.
  report(Call, C, /*Definite=*/false, DstBound.getZExtValue());
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe strcpy into fixed-size buffers; suggest strscpy(..., sizeof(dest))",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
