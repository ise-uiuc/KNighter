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

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;

  // Fallback: obtain VarRegion directly from AST DeclRefExpr of an array.
  const MemRegion *getVarRegionFromArrayDRE(const Expr *E, CheckerContext &C) const;

  // Remove mappings for any arrays that currently associate to LenReg.
  ProgramStateRef removeLenMappingsForRegion(ProgramStateRef State,
                                             const MemRegion *LenReg) const;
};

bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  // Use textual match as recommended to be robust with macros and wrappers.
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

const MemRegion *SAGenTestChecker::getVarRegionFromArrayDRE(const Expr *E,
                                                            CheckerContext &C) const {
  const Expr *EE = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!EE)
    return nullptr;
  const auto *DRE = dyn_cast<DeclRefExpr>(EE);
  if (!DRE)
    return nullptr;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  // Ensure it's a constant-sized array variable.
  QualType QT = VD->getType();
  if (!isa<ConstantArrayType>(QT.getTypePtr()))
    return nullptr;

  RegionManager &RM = C.getSValBuilder().getRegionManager();
  const VarRegion *VR = RM.getVarRegion(VD, C.getLocationContext());
  return VR ? VR->getBaseRegion() : nullptr;
}

bool SAGenTestChecker::exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                                 StringRef ArrName, CheckerContext &C) const {
  if (!E || !ArrReg)
    return false;

  // AST-based check: find a sizeof(...) inside E that references the same array
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(E)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        // Try to resolve to the same array region.
        const MemRegion *SizeofMR = getMemRegionFromExpr(Arg, C);
        if (!SizeofMR) {
          // Fallback for unevaluated sizeof argument: build VarRegion from AST.
          SizeofMR = getVarRegionFromArrayDRE(Arg, C);
        }
        if (SizeofMR) {
          SizeofMR = SizeofMR->getBaseRegion();
          if (SizeofMR == ArrReg)
            return true;
        }
      }
    }
  }

  // Textual fallback heuristic: expression contains both "sizeof" and the array's name
  if (!ArrName.empty() && ExprHasName(E, "sizeof", C) && ExprHasName(E, ArrName, C))
    return true;

  return false;
}

void SAGenTestChecker::getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                                               const MemRegion* &LenReg, SymbolRef &LenSym) const {
  LenReg = nullptr;
  LenSym = nullptr;

  ProgramStateRef State = C.getState();

  // Try to get region from state
  const MemRegion *MR = getMemRegionFromExpr(LenArg, C);
  if (MR) {
    MR = MR->getBaseRegion();
    LenReg = MR;
  }

  // Try to get symbol
  SVal SV = State->getSVal(LenArg, C.getLocationContext());
  LenSym = SV.getAsSymbol();
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

ProgramStateRef SAGenTestChecker::removeLenMappingsForRegion(ProgramStateRef State,
                                                             const MemRegion *LenReg) const {
  if (!LenReg)
    return State;
  auto Map = State->get<ArraySafeLenMap>();
  SmallVector<const MemRegion*, 4> ToRemove;
  for (auto It = Map.begin(), End = Map.end(); It != End; ++It) {
    const MemRegion *ArrMR = It->first;
    const MemRegion *LReg = It->second;
    if (LReg == LenReg)
      ToRemove.push_back(ArrMR);
  }
  for (const MemRegion *ArrMR : ToRemove)
    State = State->remove<ArraySafeLenMap>(ArrMR);
  return State;
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

  bool Recorded = false;

  // Look for sizeof(array) in RHS; if found, associate the array with this LHS length variable
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        // Confirm it's a constant array.
        llvm::APInt DummySize;
        if (getArraySizeFromExpr(DummySize, Arg)) {
          // Try state-based region first, then AST-based fallback due to unevaluated context.
          const MemRegion *ArrMR = getMemRegionFromExpr(Arg, C);
          if (!ArrMR)
            ArrMR = getVarRegionFromArrayDRE(Arg, C);
          if (ArrMR) {
            ArrMR = ArrMR->getBaseRegion();
            if (ArrMR) {
              State = State->set<ArraySafeLenMap>(ArrMR, LHSReg);
              Recorded = true;
            }
          }
        }
      }
    }
  }

  // Weak heuristic: if RHS contains both min and sizeof, consider LHS symbol bounded
  if (!Recorded && ExprHasName(RHS, "min", C) && ExprHasName(RHS, "sizeof", C)) {
    if (SymbolRef Sym = Val.getAsSymbol())
      State = State->add<BoundedLenSyms>(Sym);
  }

  // If RHS didn't contain any sizeof(...) at all, and this LHSReg was previously
  // considered a "safe length" for any array, drop those associations to avoid
  // suppressing real bugs after reassignment.
  if (!ExprHasName(RHS, "sizeof", C)) {
    State = removeLenMappingsForRegion(State, LHSReg);
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

  // 1) Len directly contains sizeof(array)
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
    // If definitely larger than the array, report.
    if (ConstLen.isSigned() ? ConstLen.getSExtValue() > (int64_t)ArraySize
                            : ConstLen.getZExtValue() > ArraySize) {
      reportUnbounded(Call, DstArg, LenArg, C);
      return;
    }
    // If definitely <= SafeCopyLimit, consider safe.
    if (ConstLen.isSigned() ? ConstLen.getSExtValue() <= (int64_t)SafeCopyLimit
                            : ConstLen.getZExtValue() <= SafeCopyLimit) {
      return;
    }
    // Otherwise, do not early report here; continue checks.
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
    // Weak heuristic: if we heuristically said the symbol is bounded, accept it.
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

- Error Line: 130 |   RegionManager &RM = C.getSValBuilder().getRegionManager();

	- Error Messages: ‘RegionManager’ was not declared in this scope

- Error Line: 130 |   RegionManager &RM = C.getSValBuilder().getRegionManager();

	- Error Messages: ‘RM’ was not declared in this scope



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
