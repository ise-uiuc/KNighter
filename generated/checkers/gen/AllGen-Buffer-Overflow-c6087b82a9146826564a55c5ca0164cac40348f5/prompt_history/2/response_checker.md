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
#include "clang/Lex/Lexer.h"
#include <string>
#include <algorithm>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded copy_from_user into fixed-size buffer", "Security")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Helper predicates/utilities
      bool isCopyFromUser(const CallEvent &Call, CheckerContext &C) const;
      bool getDestArrayAndSize(const Expr *DestArg, std::string &BufName, llvm::APInt &ArraySize) const;
      bool exprIsStaticallyBoundedByBufMinusOne(const Expr *LenExpr, StringRef BufName, unsigned BufSize, CheckerContext &C) const;
      bool exprLooksLikeRawUserLen(const Expr *LenExpr) const;
};

bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, "copy_from_user", C);
}

bool SAGenTestChecker::getDestArrayAndSize(const Expr *DestArg, std::string &BufName, llvm::APInt &ArraySize) const {
  if (!DestArg)
    return false;

  // Try to retrieve constant array size directly (helper ignores implicit nodes).
  if (!getArraySizeFromExpr(ArraySize, DestArg))
    return false;

  // Extract variable name for heuristics.
  const Expr *E = DestArg->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    DRE = findSpecificTypeInChildren<DeclRefExpr>(DestArg);
  if (!DRE)
    return false;

  if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
    BufName = VD->getNameAsString();
    return true;
  }
  return false;
}

bool SAGenTestChecker::exprIsStaticallyBoundedByBufMinusOne(const Expr *LenExpr, StringRef BufName, unsigned BufSize, CheckerContext &C) const {
  if (!LenExpr || BufSize == 0)
    return false;

  // 1) Constant evaluation
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, LenExpr, C)) {
    uint64_t V = EvalRes.getLimitedValue();
    if (V <= (uint64_t)BufSize - 1)
      return true;
    else
      return false;
  }

  // 2) Symbolic max bound
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(LenExpr, C.getLocationContext());
  if (SymbolRef Sym = SV.getAsSymbol()) {
    if (const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C)) {
      if (MaxVal->getLimitedValue() <= (uint64_t)BufSize - 1)
        return true;
      else
        return false;
    }
  }

  // 3) Heuristics: look for min(sizeof(buf)-1, ...) patterns
  // If min(...) is used and either sizeof or buffer name is referenced, assume bounded.
  if (ExprHasName(LenExpr, "min", C) &&
      (ExprHasName(LenExpr, "sizeof", C) || (!BufName.empty() && ExprHasName(LenExpr, BufName, C)))) {
    return true;
  }

  // If sizeof(buffer) and "-1" present in the expression, assume bounded.
  if ((!BufName.empty() && ExprHasName(LenExpr, BufName, C)) &&
      ExprHasName(LenExpr, "sizeof", C) &&
      (ExprHasName(LenExpr, "- 1", C) || ExprHasName(LenExpr, "-1", C))) {
    return true;
  }

  return false;
}

bool SAGenTestChecker::exprLooksLikeRawUserLen(const Expr *LenExpr) const {
  if (!LenExpr)
    return false;
  const Expr *E = LenExpr->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      std::string Name = VD->getNameAsString();
      std::string Lower = Name;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      static const char *Common[] = {"nbytes", "len", "length", "count", "size", "n", "nr", "num"};
      for (const char *S : Common) {
        if (Lower == S)
          return true;
      }
    }
  }
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCopyFromUser(Call, C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DestArg = Call.getArgExpr(0);
  const Expr *LenExpr = Call.getArgExpr(2);
  if (!DestArg || !LenExpr)
    return;

  // Destination must be a fixed-size array for our pattern.
  std::string BufName;
  llvm::APInt ArraySize;
  if (!getDestArrayAndSize(DestArg, BufName, ArraySize))
    return;

  uint64_t BufSize = ArraySize.getLimitedValue();
  if (BufSize == 0)
    return;

  // If length is bounded by sizeof(buf)-1, consider safe.
  if (exprIsStaticallyBoundedByBufMinusOne(LenExpr, BufName, (unsigned)BufSize, C))
    return;

  // If constant, check if it's > BufSize - 1 (unsafe).
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, LenExpr, C)) {
    uint64_t V = EvalRes.getLimitedValue();
    if (V <= (uint64_t)BufSize - 1)
      return; // safe
    // else unsafe, report
  } else {
    // If symbolic and we can prove max <= BufSize - 1, safe.
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(LenExpr, C.getLocationContext());
    if (SymbolRef Sym = SV.getAsSymbol()) {
      if (const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C)) {
        if (MaxVal->getLimitedValue() <= (uint64_t)BufSize - 1)
          return; // safe
      }
    }
    // Otherwise, only warn if it looks like a raw user length (e.g., nbytes)
    if (!exprLooksLikeRawUserLen(LenExpr))
      return; // avoid noise
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_from_user length not bounded by sizeof(buffer) - 1; possible overflow", N);
  R->addRange(DestArg->getSourceRange());
  R->addRange(LenExpr->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded copy_from_user into fixed-size buffers (missing sizeof(buf)-1 clamp)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
