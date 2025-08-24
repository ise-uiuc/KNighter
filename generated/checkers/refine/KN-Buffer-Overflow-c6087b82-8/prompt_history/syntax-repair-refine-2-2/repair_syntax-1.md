## Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

## Instruction

The following checker fails to compile, and your task is to resolve the compilation error based on the provided error messages.

Here are some potential ways to fix the issue:

1. Use the correct API: The current API may not exist, or the class has no such member. Replace it with an appropriate one.

2. Use correct arguments: Ensure the arguments passed to the API have the correct types and the correct number.

3. Change the variable types: Adjust the types of some variables based on the error messages.

4. Be careful if you want to include a header file. Please make sure the header file exists. For instance "fatal error: clang/StaticAnalyzer/Core/PathDiagnostic.h: No such file or directory".

**The version of Clang environment is Clang-18. You should consider the API compatibility.**

**Please only repair the failed parts and keep the original semantics.**
**Please return the whole checker code after fixing the compilation error.**

## Suggestions

1. Please only use two types of bug reports:
  - BasicBugReport (const BugType &bt, StringRef desc, PathDiagnosticLocation l)
  - PathSensitiveBugReport (const BugType &bt, StringRef desc, const ExplodedNode *errorNode)
  - PathSensitiveBugReport (const BugType &bt, StringRef shortDesc, StringRef desc, const ExplodedNode *errorNode)

## Example

- Error Line: 48 |   Optional<DefinedOrUnknownSVal> SizeSVal;

  - Error Messages: ‘Optional’ was not declared in this scope; did you mean ‘clang::ObjCImplementationControl::Optional’?

  - Fix: Replace 'Optional<DefinedOrUnknownSVal>' with 'std::optional<DefinedOrUnknownSVal>', and include the appropriate header.

- Error Line: 113 |     const MemRegion *MR = Entry.first;

    - Error Messages: unused variable ‘MR’ [-Wunused-variable]

    - Fix: Remove the variable 'MR' if it is not used.

## Checker

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

using namespace clang;
using namespace ento;
using namespace taint;

// Map: for a given destination array region (key), remember the region of a "safe length" variable
// that was computed using sizeof(that array).
REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenMap, const MemRegion*, const MemRegion*)
// Optional fallback: symbols that we heuristically believe are bounded by some sizeof()
REGISTER_SET_WITH_PROGRAMSTATE(BoundedLenSyms, SymbolRef)
// Reverse map: for a given length variable region, remember which array region it safely bounds.
// This helps us drop stale associations on reassignment.
REGISTER_MAP_WITH_PROGRAMSTATE(LenToArrayMap, const MemRegion*, const MemRegion*)

namespace {

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

  // Determine if expression E contains sizeof() on the destination array.
  bool exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                 StringRef ArrName, CheckerContext &C) const;

  // Extract region and/or symbol for length expression.
  void getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                               const MemRegion* &LenReg, SymbolRef &LenSym) const;

  // Analyze RHS expression to decide whether it establishes upper bound based on sizeof(Arr).
  bool rhsEstablishesUpperBoundForArray(const Expr *RHS,
                                        const MemRegion* &ArrRegOut,
                                        CheckerContext &C) const;

  // Helpers for rhsEstablishesUpperBoundForArray
  const Expr* ignoreParenImpCasts(const Expr *E) const {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }
  bool isSizeofOfArrayExpr(const Expr *E, const MemRegion* &ArrRegOut,
                           CheckerContext &C) const;
  bool isSizeofMinusConstExpr(const Expr *E, const MemRegion* &ArrRegOut,
                              CheckerContext &C) const;
  bool extractUpperBoundExprArr(const Expr *E, const MemRegion* &ArrRegOut,
                                CheckerContext &C) const;
  bool isMinLikeTernaryWithUB(const Expr *RHS, const MemRegion* &ArrRegOut,
                              CheckerContext &C) const;

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;
};

bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
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

  if (!getArraySizeFromExpr(ArraySize, DstArg))
    return false;

  const MemRegion *MR = getMemRegionFromExpr(DstArg, C);
  if (!MR)
    return false;
  MR = MR->getBaseRegion();
  if (!MR)
    return false;
  ArrReg = MR;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(DstArg->IgnoreImplicit())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      ArrName = VD->getNameAsString();
    }
  }

  return true;
}

bool SAGenTestChecker::exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                                 StringRef ArrName, CheckerContext &C) const {
  if (!E || !ArrReg)
    return false;

  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(E)) {
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

  if (!ArrName.empty() && ExprHasName(E, "sizeof", C) && ExprHasName(E, ArrName, C))
    return true;

  return false;
}

void SAGenTestChecker::getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                                               const MemRegion* &LenReg, SymbolRef &LenSym) const {
  LenReg = nullptr;
  LenSym = nullptr;

  ProgramStateRef State = C.getState();

  // Try to get region through the usual SVal lvalue path.
  const MemRegion *MR = getMemRegionFromExpr(LenArg, C);
  if (!MR) {
    // If LenArg is a DeclRefExpr (rvalue), construct its LValue to obtain the region.
    if (const auto *DRE = dyn_cast_or_null<DeclRefExpr>(LenArg ? LenArg->IgnoreImplicit() : nullptr)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        SVal LV = C.getSValBuilder().getLValue(VD, C.getLocationContext());
        MR = LV.getAsRegion();
      }
    }
  }
  if (MR) {
    MR = MR->getBaseRegion();
    LenReg = MR;
  }

  // Try to get symbol
  SVal SV = State->getSVal(LenArg, C.getLocationContext());
  LenSym = SV.getAsSymbol();
}

bool SAGenTestChecker::isSizeofOfArrayExpr(const Expr *E, const MemRegion* &ArrRegOut,
                                           CheckerContext &C) const {
  ArrRegOut = nullptr;
  const Expr *IE = ignoreParenImpCasts(E);
  const auto *UE = dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(IE);
  if (!UE || UE->getKind() != UETT_SizeOf)
    return false;
  const Expr *Arg = UE->getArgumentExpr();
  if (!Arg)
    return false;
  llvm::APInt DummySize;
  if (!getArraySizeFromExpr(DummySize, Arg))
    return false;
  const MemRegion *MR = getMemRegionFromExpr(Arg, C);
  if (!MR)
    return false;
  MR = MR->getBaseRegion();
  if (!MR)
    return false;
  ArrRegOut = MR;
  return true;
}

bool SAGenTestChecker::isSizeofMinusConstExpr(const Expr *E, const MemRegion* &ArrRegOut,
                                              CheckerContext &C) const {
  ArrRegOut = nullptr;
  const Expr *IE = ignoreParenImpCasts(E);
  const auto *BO = dyn_cast_or_null<BinaryOperator>(IE);
  if (!BO || BO->getOpcode() != BO_Sub)
    return false;
  const Expr *L = ignoreParenImpCasts(BO->getLHS());
  const Expr *R = ignoreParenImpCasts(BO->getRHS());
  const auto *UE = dyn_cast<UnaryExprOrTypeTraitExpr>(L);
  if (!UE || UE->getKind() != UETT_SizeOf)
    return false;

  // RHS must be an integer constant (>= 0)
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, R, C))
    return false;

  const Expr *Arg = UE->getArgumentExpr();
  if (!Arg)
    return false;
  llvm::APInt DummySize;
  if (!getArraySizeFromExpr(DummySize, Arg))
    return false;
  const MemRegion *MR = getMemRegionFromExpr(Arg, C);
  if (!MR)
    return false;
  MR = MR->getBaseRegion();
  if (!MR)
    return false;

  ArrRegOut = MR;
  return true;
}

bool SAGenTestChecker::extractUpperBoundExprArr(const Expr *E, const MemRegion* &ArrRegOut,
                                                CheckerContext &C) const {
  // UB is sizeof(arr) or sizeof(arr) - const
  if (isSizeofOfArrayExpr(E, ArrRegOut, C))
    return true;
  if (isSizeofMinusConstExpr(E, ArrRegOut, C))
    return true;
  return false;
}

bool SAGenTestChecker::isMinLikeTernaryWithUB(const Expr *RHS, const MemRegion* &ArrRegOut,
                                              CheckerContext &C) const {
  ArrRegOut = nullptr;
  const auto *CO = dyn_cast_or_null<ConditionalOperator>(ignoreParenImpCasts(RHS));
  if (!CO)
    return false;

  const Expr *Cond = ignoreParenImpCasts(CO->getCond());
  const Expr *TrueE = ignoreParenImpCasts(CO->getTrueExpr());
  const Expr *FalseE = ignoreParenImpCasts(CO->getFalseExpr());

  const auto *BO = dyn_cast_or_null<BinaryOperator>(Cond);
  if (!BO)
    return false;

  const Expr *CL = ignoreParenImpCasts(BO->getLHS());
  const Expr *CR = ignoreParenImpCasts(BO->getRHS());

  const MemRegion *UBArrL = nullptr, *UBArrR = nullptr;
  bool LIsUB = extractUpperBoundExprArr(CL, UBArrL, C);
  bool RIsUB = extractUpperBoundExprArr(CR, UBArrR, C);

  BinaryOperatorKind Op = BO->getOpcode();

  // Helper lambda: check if branch selection matches min pattern
  auto matchPattern = [&](bool UBIsRHS, BinaryOperatorKind OpK,
                          const Expr *TrueB, const Expr *FalseB,
                          const MemRegion *UBArr) -> bool {
    if (!UBArr)
      return false;
    // If UB is RHS:
    //   X > UB  ? UB : X   (True branch = UB)
    //   X >= UB ? UB : X
    //   X < UB  ? X  : UB  (False branch = UB)
    //   X <= UB ? X  : UB
    if (UBIsRHS) {
      if ((OpK == BO_GT || OpK == BO_GE)) {
        if (extractUpperBoundExprArr(TrueB, ArrRegOut, C) && ArrRegOut == UBArr)
          return true;
      } else if ((OpK == BO_LT || OpK == BO_LE)) {
        if (extractUpperBoundExprArr(FalseB, ArrRegOut, C) && ArrRegOut == UBArr)
          return true;
      }
    } else {
      // If UB is LHS:
      //   UB < X  ? UB : X  (True branch = UB)
      //   UB <= X ? UB : X
      //   UB > X  ? X  : UB (False branch = UB)
      //   UB >= X ? X  : UB
      if ((OpK == BO_LT || OpK == BO_LE)) {
        if (extractUpperBoundExprArr(TrueB, ArrRegOut, C) && ArrRegOut == UBArr)
          return true;
      } else if ((OpK == BO_GT || OpK == BO_GE)) {
        if (extractUpperBoundExprArr(FalseB, ArrRegOut, C) && ArrRegOut == UBArr)
          return true;
      }
    }
    ArrRegOut = nullptr;
    return false;
  };

  if (RIsUB && matchPattern(/*UBIsRHS=*/true, Op, TrueE, FalseE, UBArrR))
    return true;
  if (LIsUB && matchPattern(/*UBIsRHS=*/false, Op, TrueE, FalseE, UBArrL))
    return true;

  return false;
}

bool SAGenTestChecker::rhsEstablishesUpperBoundForArray(const Expr *RHS,
                                                        const MemRegion* &ArrRegOut,
                                                        CheckerContext &C) const {
  ArrRegOut = nullptr;
  const Expr *IE = ignoreParenImpCasts(RHS);

  // Direct bound: sizeof(arr) or sizeof(arr) - const
  if (extractUpperBoundExprArr(IE, ArrRegOut, C))
    return true;

  // Ternary min pattern: (X > sizeof(arr)-k ? sizeof(arr)-k : X) etc.
  if (isMinLikeTernaryWithUB(IE, ArrRegOut, C))
    return true;

  // Heuristic: min(...) macro with sizeof(array)
  if (ExprHasName(RHS, "min", C) || ExprHasName(RHS, "min_t", C)) {
    // Try to confirm sizeof refers to an array and extract it
    const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS);
    if (UE && UE->getKind() == UETT_SizeOf) {
      const Expr *Arg = UE->getArgumentExpr();
      llvm::APInt DummySize;
      if (Arg && getArraySizeFromExpr(DummySize, Arg)) {
        const MemRegion *MR = getMemRegionFromExpr(Arg, C);
        if (MR) {
          MR = MR->getBaseRegion();
          if (MR) {
            ArrRegOut = MR;
            return true;
          }
        }
      }
    }
  }

  return false;
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

  // Drop stale association if this length variable was previously tied to some array.
  if (const MemRegion *const *OldArrPtr = State->get<LenToArrayMap>(LHSReg)) {
    const MemRegion *OldArr = *OldArrPtr;
    // Remove both sides of the mapping.
    State = State->remove<ArraySafeLenMap>(OldArr);
    State = State->remove<LenToArrayMap>(LHSReg);
  }

  // Try to see if RHS establishes a bound based on sizeof(array)
  const MemRegion *ArrMR = nullptr;
  if (rhsEstablishesUpperBoundForArray(RHS, ArrMR, C)) {
    if (ArrMR) {
      State = State->set<ArraySafeLenMap>(ArrMR, LHSReg);
      State = State->set<LenToArrayMap>(LHSReg, ArrMR);
      C.addTransition(State);
      return;
    }
  } else {
    // Weak heuristic: if RHS contains both min and sizeof, consider LHS symbol bounded (fallback).
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

  // Identify destination as a fixed-size array
  llvm::APInt ArraySizeAP;
  const MemRegion *ArrReg = nullptr;
  std::string ArrName;
  if (!getDestArrayInfo(DstArg, C, ArraySizeAP, ArrReg, ArrName))
    return; // Only warn when destination is a provable fixed-size array

  uint64_t ArraySize = ArraySizeAP.getZExtValue();
  uint64_t SafeCopyLimit = (ArraySize > 0) ? (ArraySize - 1) : 0;

  // 1) Len directly contains sizeof(array) (e.g., min in-call)
  if (exprContainsSizeofOfArray(LenArg, ArrReg, ArrName, C))
    return;

  ProgramStateRef State = C.getState();

  // 2) Len is a variable that we already recorded as safe for this array
  const MemRegion *const *BoundRegForArrayPtr = State->get<ArraySafeLenMap>(ArrReg);
  const MemRegion *BoundRegForArray = BoundRegForArrayPtr ? *BoundRegForArrayPtr : nullptr;
  const MemRegion *LenReg = nullptr;
  SymbolRef LenSym = nullptr;
  getLenArgRegionOrSymbol(LenArg, C, LenReg, LenSym);
  if (BoundRegForArray && LenReg && (BoundRegForArray == LenReg))
    return;

  // 3) Try to infer if Len is constant and exceeds the array size
  llvm::APSInt ConstLen;
  if (EvaluateExprToInt(ConstLen, LenArg, C)) {
    if (ConstLen.isSigned() ? ConstLen.getSExtValue() > (int64_t)ArraySize
                            : ConstLen.getZExtValue() > ArraySize) {
      reportUnbounded(Call, DstArg, LenArg, C);
      return;
    }
    if (ConstLen.isSigned() ? ConstLen.getSExtValue() <= (int64_t)SafeCopyLimit
                            : ConstLen.getZExtValue() <= SafeCopyLimit) {
      return;
    }
    // Otherwise, continue checks.
  }

  // 4) Infer maximal value for symbolic Len
  if (LenSym) {
    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(LenSym, C)) {
      uint64_t MaxVal = MaxV->isSigned() ? (uint64_t)MaxV->getSExtValue() : MaxV->getZExtValue();
      if (MaxVal <= SafeCopyLimit)
        return; // safely bounded
      if (MaxVal > ArraySize) {
        // Definitely can exceed buffer size.
        reportUnbounded(Call, DstArg, LenArg, C);
        return;
      }
    }
    if (State->contains<BoundedLenSyms>(LenSym))
      return;
  }

  // 5) If none of the above proved it's safe, warn.
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

## Error Messages

- Error Line: 160 |         SVal LV = C.getSValBuilder().getLValue(VD, C.getLocationContext());

	- Error Messages: ‘class clang::ento::SValBuilder’ has no member named ‘getLValue’; did you mean ‘getMinValue’?



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
