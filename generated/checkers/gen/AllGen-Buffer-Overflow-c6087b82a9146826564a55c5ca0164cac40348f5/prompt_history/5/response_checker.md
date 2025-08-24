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
#include "clang/AST/ExprCXX.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unbounded copy_from_user length", "Security")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Returns true if Expr text contains any of the common clamping helpers plus sizeof(dest)
  bool isClampedBySizeExpr(const Expr *LenE, StringRef DestName, CheckerContext &C) const;

  // Try to conclude the length is bounded by the destination's array size.
  bool isLengthProvablySafe(const Expr *LenE, const Expr *DestE,
                            const llvm::APInt &ArraySize, CheckerContext &C) const;

  // Try to conclude the variable used as length is clamped/safe, by inspecting its initializer.
  bool isLenVarInitSafe(const VarDecl *VD, StringRef DestName,
                        const llvm::APInt &ArraySize, CheckerContext &C) const;

  // Helper to evaluate constant and compare to array size.
  bool constLEArraySize(const Expr *E, const llvm::APInt &ArraySize, CheckerContext &C) const;
};

bool SAGenTestChecker::constLEArraySize(const Expr *E, const llvm::APInt &ArraySize,
                                        CheckerContext &C) const {
  if (!E)
    return false;
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, E, C))
    return false;

  uint64_t LenVal = EvalRes.isSigned() ? (uint64_t)EvalRes.getSExtValue()
                                       : EvalRes.getZExtValue();
  uint64_t ArrSz = ArraySize.getLimitedValue(UINT64_MAX);
  return LenVal <= ArrSz;
}

bool SAGenTestChecker::isClampedBySizeExpr(const Expr *LenE, StringRef DestName,
                                           CheckerContext &C) const {
  if (!LenE)
    return false;
  // Recognize common clamp idioms: min/min_t/min3/clamp with sizeof(dest)
  bool HasClampFunc = ExprHasName(LenE, "min", C) ||
                      ExprHasName(LenE, "min_t", C) ||
                      ExprHasName(LenE, "min3", C) ||
                      ExprHasName(LenE, "clamp", C);
  if (!HasClampFunc)
    return false;

  if (!DestName.empty()) {
    std::string SizeofDest = ("sizeof(" + DestName + ")").str();
    if (ExprHasName(LenE, SizeofDest, C))
      return true;
  }
  // If we cannot match the exact destination name in sizeof, be conservative: do not claim safe.
  return false;
}

bool SAGenTestChecker::isLenVarInitSafe(const VarDecl *VD, StringRef DestName,
                                        const llvm::APInt &ArraySize,
                                        CheckerContext &C) const {
  if (!VD || !VD->hasInit())
    return false;

  const Expr *Init = VD->getInit();
  if (!Init)
    return false;

  // Constant <= array size
  if (constLEArraySize(Init, ArraySize, C))
    return true;

  // Clamp idiom using sizeof(dest)
  if (isClampedBySizeExpr(Init, DestName, C))
    return true;

  // We can try to see if Init has a symbolic max <= array size.
  SVal InitVal = C.getState()->getSVal(Init, C.getLocationContext());
  if (SymbolRef Sym = InitVal.getAsSymbol()) {
    if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
      uint64_t MaxV = Max->isSigned() ? (uint64_t)Max->getSExtValue()
                                      : Max->getZExtValue();
      uint64_t ArrSz = ArraySize.getLimitedValue(UINT64_MAX);
      if (MaxV <= ArrSz)
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::isLengthProvablySafe(const Expr *LenE, const Expr *DestE,
                                            const llvm::APInt &ArraySize,
                                            CheckerContext &C) const {
  if (!LenE || !DestE)
    return false;

  // 1) Constant evaluation
  if (constLEArraySize(LenE, ArraySize, C))
    return true;

  // Determine destination variable name if available
  StringRef DestName;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(DestE->IgnoreImplicit())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      DestName = VD->getName();
    }
  }

  // 2) Symbolic maximum
  SVal LenVal = C.getState()->getSVal(LenE, C.getLocationContext());
  if (SymbolRef Sym = LenVal.getAsSymbol()) {
    if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
      uint64_t MaxV = Max->isSigned() ? (uint64_t)Max->getSExtValue()
                                      : Max->getZExtValue();
      uint64_t ArrSz = ArraySize.getLimitedValue(UINT64_MAX);
      if (MaxV <= ArrSz)
        return true;
    }
  }

  // 3) Clamp idioms e.g. min(nbytes, sizeof(buf)[-1])
  if (isClampedBySizeExpr(LenE, DestName, C))
    return true;

  // 4) If Len is a variable, check its initializer for clamping patterns
  if (const auto *LenDRE = dyn_cast<DeclRefExpr>(LenE->IgnoreParenCasts())) {
    if (const auto *LenVD = dyn_cast<VarDecl>(LenDRE->getDecl())) {
      if (isLenVarInitSafe(LenVD, DestName, ArraySize, C))
        return true;
    }
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Verify function name via expression text
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "copy_from_user", C))
    return;

  // Expect 3 arguments: (dst, src, len)
  if (Call.getNumArgs() != 3)
    return;

  const Expr *DestE = Call.getArgExpr(0);
  const Expr *LenE  = Call.getArgExpr(2);
  if (!DestE || !LenE)
    return;

  // Destination must be a fixed-size array we can reason about
  llvm::APInt ArraySize;
  if (!getArraySizeFromExpr(ArraySize, DestE))
    return; // Unknown destination bound; avoid false positives

  // If length is not provably <= sizeof(dest), warn
  if (!isLengthProvablySafe(LenE, DestE, ArraySize, C)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "copy_from_user length not clamped to destination buffer size", N);

    if (const auto *CE = dyn_cast<CallExpr>(OriginExpr))
      R->addRange(CE->getSourceRange());
    R->addRange(DestE->getSourceRange());
    R->addRange(LenE->getSourceRange());

    R->addNote("Clamp length, e.g., min(nbytes, sizeof(buf) - 1), and use the "
               "clamped value for both copy and return size if applicable.",
               PathDiagnosticLocation::createBegin(OriginExpr, C.getSourceManager(),
                                                   C.getLocationContext()));
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect unbounded copy_from_user into fixed-size buffers (possible overflow)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
