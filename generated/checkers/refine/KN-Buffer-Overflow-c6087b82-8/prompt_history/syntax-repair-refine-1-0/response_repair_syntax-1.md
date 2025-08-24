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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include <algorithm>
#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Map: for a given destination array region (key), remember the region of a "safe length" variable
// that was computed using sizeof(that array).
REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenMap, const MemRegion*, const MemRegion*)
// Optional fallback: symbols that we heuristically believe are bounded by some sizeof()
REGISTER_SET_WITH_PROGRAMSTATE(BoundedLenSyms, SymbolRef)

namespace {

// Utility functions provided in the prompt (assumed available):
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool functionKnownToDeref(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

class SAGenTestChecker
  : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unbounded copy_from_user", "Memory Safety")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper functions
  bool isCopyFromUser(const CallEvent &Call, CheckerContext &C) const;

  // Try to identify destination as a fixed-size array. Returns true on success and fills ArraySize, ArrReg, ArrName.
  bool getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                        std::string &ArrName) const;

  // Determine if length expression is safely bounded by sizeof(array) or sizeof(array) - K.
  bool exprIsBoundedBySizeofArray(const Expr *E, const MemRegion *ArrReg,
                                  StringRef ArrName, uint64_t ArraySize,
                                  CheckerContext &C) const;

  // Extract region and/or symbol for length expression.
  void getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                               const MemRegion* &LenReg, SymbolRef &LenSym) const;

  // Additional FP guard: detect trivial safe cases quickly.
  bool isFalsePositiveConstantLen(const Expr *LenArg, uint64_t ArraySize,
                                  CheckerContext &C) const;

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;
};

bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  // Use textual match to be robust against macros/wrappers in kernel headers.
  if (ExprHasName(OE, "copy_from_user", C))
    return true;
  if (ExprHasName(OE, "__copy_from_user", C))
    return true;
  if (ExprHasName(OE, "raw_copy_from_user", C))
    return true;
  return false;
}

bool SAGenTestChecker::getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                                        std::string &ArrName) const {
  ArrReg = nullptr;
  ArrName.clear();

  // Identify that DstArg is a fixed-size array and retrieve its size
  if (!getArraySizeFromExpr(ArraySize, DstArg))
    return false;

  // Retrieve the region of the destination and normalize to base region
  const MemRegion *MR = getMemRegionFromExpr(DstArg, C);
  if (!MR)
    return false;
  MR = MR->getBaseRegion();
  if (!MR)
    return false;
  ArrReg = MR;

  // Try extracting the array variable name
  if (const auto *DRE = dyn_cast<DeclRefExpr>(DstArg->IgnoreImplicit())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      ArrName = VD->getNameAsString();
    }
  }

  return true;
}

// Return true only if the expression is clearly bounded by sizeof(array) or sizeof(array)-K.
// Examples accepted as bounded:
//   - sizeof(arr)
//   - sizeof(arr) - 1, sizeof(arr) - K (K >= 0)
//   - min(nbytes, sizeof(arr)), min(nbytes, sizeof(arr) - 1), min(..., sizeof(arr) - K)
// The "min" detection is heuristic (textual). We purposely do NOT accept expressions like
//   sizeof(arr) + 1, or arbitrary usage where sizeof(arr) appears but doesn't bound the result.
bool SAGenTestChecker::exprIsBoundedBySizeofArray(const Expr *E, const MemRegion *ArrReg,
                                                  StringRef ArrName, uint64_t ArraySize,
                                                  CheckerContext &C) const {
  if (!E || !ArrReg)
    return false;

  // 1) Exactly sizeof(array)
  if (const auto *UE = dyn_cast<UnaryExprOrTypeTraitExpr>(E->IgnoreParenCasts())) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        const MemRegion *SizeofMR = getMemRegionFromExpr(Arg, C);
        if (SizeofMR) {
          SizeofMR = SizeofMR->getBaseRegion();
          if (SizeofMR == ArrReg)
            return true;
        }
      }
    }
  }

  // 2) sizeof(array) - K, where K is a non-negative integer constant
  if (const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenCasts())) {
    if (BO->getOpcode() == BO_Sub) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      const auto *UE = dyn_cast<UnaryExprOrTypeTraitExpr>(LHS);
      if (UE && UE->getKind() == UETT_SizeOf) {
        if (const Expr *Arg = UE->getArgumentExpr()) {
          const MemRegion *SizeofMR = getMemRegionFromExpr(Arg, C);
          if (SizeofMR) {
            SizeofMR = SizeofMR->getBaseRegion();
            if (SizeofMR == ArrReg) {
              llvm::APSInt K;
              if (EvaluateExprToInt(K, RHS, C)) {
                // Accept only if RHS is non-negative and does not exceed ArraySize
                uint64_t KV = K.isSigned() ? (uint64_t)std::max<int64_t>(0, K.getSExtValue())
                                           : K.getZExtValue();
                if (KV <= ArraySize)
                  return true;
              }
            }
          }
        }
      }
    }
  }

  // 3) Heuristic: expression uses min(...) with sizeof(array) or sizeof(array)-K inside.
  // This recognizes Linux's min()/min_t() macros in source.
  if (ExprHasName(E, "min", C)) {
    // If there's a sizeof(arr) somewhere in the expression, and "min" appears, accept as bounded.
    if (const auto *AnyUE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(E)) {
      if (AnyUE->getKind() == UETT_SizeOf) {
        if (const Expr *Arg = AnyUE->getArgumentExpr()) {
          const MemRegion *SizeofMR = getMemRegionFromExpr(Arg, C);
          if (SizeofMR) {
            SizeofMR = SizeofMR->getBaseRegion();
            if (SizeofMR == ArrReg)
              return true;
          }
        }
      }
    }
    // Textual fallback: min(...) and mentions the array name alongside sizeof
    if (!ArrName.empty() && ExprHasName(E, "sizeof", C) && ExprHasName(E, ArrName, C))
      return true;
  }

  return false;
}

void SAGenTestChecker::getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                                               const MemRegion* &LenReg, SymbolRef &LenSym) const {
  LenReg = nullptr;
  LenSym = nullptr;

  ProgramStateRef State = C.getState();

  // Try to get region
  const MemRegion *MR = getMemRegionFromExpr(LenArg, C);
  if (MR) {
    MR = MR->getBaseRegion();
    LenReg = MR;
  }

  // Try to get symbol
  SVal SV = State->getSVal(LenArg, C.getLocationContext());
  LenSym = SV.getAsSymbol();
}

// If length is compile-time constant and <= ArraySize, clearly safe.
bool SAGenTestChecker::isFalsePositiveConstantLen(const Expr *LenArg, uint64_t ArraySize,
                                                  CheckerContext &C) const {
  llvm::APSInt ConstLen;
  if (!EvaluateExprToInt(ConstLen, LenArg, C))
    return false;
  uint64_t L = ConstLen.isSigned() ? (ConstLen.getSExtValue() < 0 ? 0ULL
                                                                 : (uint64_t)ConstLen.getSExtValue())
                                   : ConstLen.getZExtValue();
  return L <= ArraySize;
}

void SAGenTestChecker::reportUnbounded(const CallEvent &Call, const Expr *Dst,
                                       const Expr *Len, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_from_user length not bounded by destination buffer size", N);
  SourceRange CR = Call.getSourceRange();
  if (CR.isValid())
    R->addRange(CR);
  if (Dst)
    R->addRange(Dst->getSourceRange());
  if (Len)
    R->addRange(Len->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;

  // Look for sizeof(array) in RHS; if found, associate the array with this LHS length variable
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        // Confirm it's an array decl ref
        llvm::APInt DummySize;
        if (getArraySizeFromExpr(DummySize, Arg)) {
          const MemRegion *ArrMR = getMemRegionFromExpr(Arg, C);
          if (ArrMR) {
            ArrMR = ArrMR->getBaseRegion();
            if (ArrMR) {
              State = State->set<ArraySafeLenMap>(ArrMR, LHSReg);
            }
          }
        }
      }
    }
  } else {
    // Weak heuristic: if RHS contains both min and sizeof, consider LHS symbol bounded
    if (ExprHasName(RHS, "min", C) && ExprHasName(RHS, "sizeof", C)) {
      if (SymbolRef Sym = Val.getAsSymbol())
        State = State->add<BoundedLenSyms>(Sym);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCopyFromUser(Call, C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DstArg = Call.getArgExpr(0);
  const Expr *LenArg = Call.getArgExpr(2);
  if (!DstArg || !LenArg)
    return;

  // Identify destination as a provable fixed-size array
  llvm::APInt ArraySizeAP;
  const MemRegion *ArrReg = nullptr;
  std::string ArrName;
  if (!getDestArrayInfo(DstArg, C, ArraySizeAP, ArrReg, ArrName))
    return; // Only warn when destination is a provable fixed-size array

  uint64_t ArraySize = ArraySizeAP.getZExtValue();

  ProgramStateRef State = C.getState();

  // Heuristic 1: If the length expression is clearly bounded by sizeof(array)
  // (or sizeof(array) - K / min(..., sizeof(array) [- K])), accept as safe.
  if (exprIsBoundedBySizeofArray(LenArg, ArrReg, ArrName, ArraySize, C))
    return;

  // Heuristic 2: Constant length <= ArraySize is safe (e.g. IFNAMSIZ into char buf[IFNAMSIZ]).
  if (isFalsePositiveConstantLen(LenArg, ArraySize, C))
    return;

  // Heuristic 3: Len is a variable recorded as safe for this array (computed from sizeof(arr)).
  const MemRegion *const *BoundRegForArrayPtr = State->get<ArraySafeLenMap>(ArrReg);
  const MemRegion *BoundRegForArray = BoundRegForArrayPtr ? *BoundRegForArrayPtr : nullptr;
  const MemRegion *LenReg = nullptr;
  SymbolRef LenSym = nullptr;
  getLenArgRegionOrSymbol(LenArg, C, LenReg, LenSym);
  if (BoundRegForArray && LenReg && (BoundRegForArray == LenReg))
    return;

  // Constant length > ArraySize is definitely unsafe.
  llvm::APSInt ConstLen;
  if (EvaluateExprToInt(ConstLen, LenArg, C)) {
    uint64_t L = ConstLen.isSigned() ? (ConstLen.getSExtValue() < 0 ? 0ULL
                                                                    : (uint64_t)ConstLen.getSExtValue())
                                     : ConstLen.getZExtValue();
    if (L > ArraySize) {
      reportUnbounded(Call, DstArg, LenArg, C);
      return;
    }
    // Length constant <= ArraySize handled earlier.
  }

  // Infer maximal value for symbolic Len from constraints
  if (LenSym) {
    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(LenSym, C)) {
      uint64_t MaxVal = MaxV->isSigned() ? (uint64_t)std::max<int64_t>(0, MaxV->getSExtValue())
                                         : MaxV->getZExtValue();
      if (MaxVal <= ArraySize)
        return; // safely bounded
      if (MaxVal > ArraySize) {
        // Definitely can exceed buffer size.
        reportUnbounded(Call, DstArg, LenArg, C);
        return;
      }
    }
    // Weak heuristic: if we heuristically said the symbol is bounded, accept it.
    if (State->contains<BoundedLenSyms>(LenSym))
      return;
  }

  // If none of the above proved it's safe, warn.
  reportUnbounded(Call, DstArg, LenArg, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded copy_from_user into fixed-size buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
