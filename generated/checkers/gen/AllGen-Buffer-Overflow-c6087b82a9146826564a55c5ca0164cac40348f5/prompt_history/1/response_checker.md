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
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded copy_from_user into fixed-size buffer", "Security")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Try to extract destination fixed-size array info (size and name) from an expression.
      bool getFixedArrayInfo(const Expr *DstExpr, CheckerContext &C,
                             llvm::APInt &ArraySize, std::string &DestName) const;

      // Try to determine if NExpr is syntactically clamped with min(sizeof(Dest)...)
      bool isClampedByMinSizeof(const Expr *NExpr, StringRef DestName, CheckerContext &C) const;

      // Check if a DeclRefExpr refers to an integer-like local variable with an initializer
      // that is constant and <= bound or a min(sizeof(Dest), ...) pattern.
      bool initializerProvesSafe(const DeclRefExpr *DRE, uint64_t Bound,
                                 StringRef DestName, CheckerContext &C) const;

      void report(const CallEvent &Call, const Expr *SizeExpr,
                  const Expr *DstExpr, CheckerContext &C) const;
};

bool SAGenTestChecker::getFixedArrayInfo(const Expr *DstExpr, CheckerContext &C,
                                         llvm::APInt &ArraySize, std::string &DestName) const {
  if (!DstExpr)
    return false;

  // First, try direct
  if (getArraySizeFromExpr(ArraySize, DstExpr)) {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(DstExpr->IgnoreImplicit())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        DestName = VD->getName().str();
      }
    } else {
      // Try to find a DRE for name extraction
      if (const auto *InnerDRE = findSpecificTypeInChildren<DeclRefExpr>(DstExpr)) {
        if (const auto *VD = dyn_cast<VarDecl>(InnerDRE->getDecl())) {
          DestName = VD->getName().str();
        }
      }
    }
    return true;
  }

  // Then, search downward for a DeclRefExpr that names the array variable.
  if (const auto *InnerDRE = findSpecificTypeInChildren<DeclRefExpr>(DstExpr)) {
    if (getArraySizeFromExpr(ArraySize, InnerDRE)) {
      if (const auto *VD = dyn_cast<VarDecl>(InnerDRE->getDecl())) {
        DestName = VD->getName().str();
      }
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isClampedByMinSizeof(const Expr *NExpr, StringRef DestName,
                                            CheckerContext &C) const {
  if (!NExpr)
    return false;
  // Heuristic syntactic check: size expression mentions min, sizeof, and the destination array name.
  if (ExprHasName(NExpr, "min", C) && ExprHasName(NExpr, "sizeof", C)) {
    if (!DestName.empty() && ExprHasName(NExpr, DestName, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::initializerProvesSafe(const DeclRefExpr *DRE, uint64_t Bound,
                                             StringRef DestName, CheckerContext &C) const {
  if (!DRE)
    return false;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return false;

  const Expr *Init = VD->getInit();
  if (!Init)
    return false;

  llvm::APSInt InitVal;
  if (EvaluateExprToInt(InitVal, Init, C)) {
    uint64_t InitU = InitVal.getLimitedValue();
    if (InitU <= Bound)
      return true;
  }

  // Check for syntactic clamp in initializer
  if (isClampedByMinSizeof(Init, DestName, C))
    return true;

  return false;
}

void SAGenTestChecker::report(const CallEvent &Call, const Expr *SizeExpr,
                              const Expr *DstExpr, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unbounded copy_from_user into fixed-size buffer", N);

  if (SizeExpr)
    R->addRange(SizeExpr->getSourceRange());
  if (DstExpr)
    R->addRange(DstExpr->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Identify copy_from_user by source text name to be robust with wrappers.
  if (!ExprHasName(Origin, "copy_from_user", C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DstExpr = Call.getArgExpr(0);
  const Expr *SizeExpr = Call.getArgExpr(2);
  if (!DstExpr || !SizeExpr)
    return;

  // Destination must be a fixed-size array in scope
  llvm::APInt ArraySize;
  std::string DestName;
  if (!getFixedArrayInfo(DstExpr, C, ArraySize, DestName))
    return; // Only warn for fixed-size arrays we can resolve

  uint64_t ArrSizeU = ArraySize.getLimitedValue();
  uint64_t Bound = ArrSizeU > 0 ? (ArrSizeU - 1) : 0;

  // Case A: Constant size
  llvm::APSInt ConstSizeVal;
  if (EvaluateExprToInt(ConstSizeVal, SizeExpr, C)) {
    uint64_t N = ConstSizeVal.getLimitedValue();
    if (N <= Bound)
      return; // safe
    report(Call, SizeExpr, DstExpr, C);
    return;
  }

  // Case B: Symbolic size with known maximum
  SVal NVal = Call.getArgSVal(2);
  if (SymbolRef Sym = NVal.getAsSymbol()) {
    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
      uint64_t MaxU = MaxV->getLimitedValue();
      if (MaxU <= Bound)
        return; // safe
      // else continue with other syntactic checks
    }
  }

  // Case C: Syntactic clamp pattern in the size expression itself
  if (isClampedByMinSizeof(SizeExpr, DestName, C))
    return; // safe

  // Case D: Size is a local variable with an initializer clamp
  if (const auto *SizeDRE = dyn_cast<DeclRefExpr>(SizeExpr->IgnoreParenCasts())) {
    if (initializerProvesSafe(SizeDRE, Bound, DestName, C))
      return; // safe
  }

  // If none of the above proves safety, report
  report(Call, SizeExpr, DstExpr, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded copy_from_user into fixed-size buffers (missing min(sizeof(buf)-1, nbytes) clamp)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
