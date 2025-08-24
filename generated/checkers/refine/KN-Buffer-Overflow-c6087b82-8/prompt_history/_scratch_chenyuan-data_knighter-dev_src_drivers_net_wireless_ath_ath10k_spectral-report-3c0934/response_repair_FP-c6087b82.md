Refinement Plan:
- Root cause: The checker relies on checkBind assuming S is always the BinaryOperator of an assignment. With macros like min() (as used in the kernel), the bind callback is frequently invoked for subexpressions (e.g., branches of a conditional inside min), so RHS extraction fails and we never record that the length variable was bounded by sizeof(dest) - 1. Consequently, when seeing copy_from_user(buf, user_buf, len), the checker does not know that len was already clamped, and it emits a false positive.
- Fix approach:
  1) In checkBind, robustly recover the actual assignment or declaration initializer that produced the bind by walking up to the parent BinaryOperator or DeclStmt and extracting the RHS/init expression.
  2) If the RHS/init contains sizeof(array), record a precise mapping from the destination array’s MemRegion to the length variable’s MemRegion (ArraySafeLenMap). This enables checkPreCall to recognize len as safely clamped for that specific array.
  3) Keep the existing logic that only deems safe when the length is provably bounded by the same array’s sizeof, preserving true positive detection.
- Edge cases/regressions handled:
  - Handles both assignment (len = ...) and initialization (size_t len = ...).
  - Only records safety mapping when the RHS contains sizeof(actual array), keeping precision and avoiding suppressing legitimate issues.
  - Keeps existing constant and symbolic bounds checks for true positives.
- Compatibility: No API changes beyond standard Clang 18 usage; no includes removed.

Refined Code:
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

  // Robustly extract RHS/init expression associated with the bind to LHSReg by walking up parents.
  const Expr *recoverRHSForBind(const Stmt *S, const MemRegion *LHSReg, CheckerContext &C) const;

  // Try to record that LHSReg is a safe length for some array found via sizeof in RHS/init.
  ProgramStateRef tryRecordArraySafeLen(ProgramStateRef State,
                                        const Expr *RHS,
                                        const MemRegion *LHSReg,
                                        CheckerContext &C) const;
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

bool SAGenTestChecker::exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                                 StringRef ArrName, CheckerContext &C) const {
  if (!E || !ArrReg)
    return false;

  // AST-based check: find a sizeof(...) inside E that references the same array
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

// Recover RHS of an assignment or initializer responsible for binding to LHSReg.
// This handles cases where checkBind is invoked on subexpressions inside a macro expansion.
const Expr *SAGenTestChecker::recoverRHSForBind(const Stmt *S, const MemRegion *LHSReg,
                                                CheckerContext &C) const {
  if (!S || !LHSReg)
    return nullptr;

  // Direct assignment
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      return BO->getRHS();
  }

  // Walk up to the nearest assignment
  if (const auto *PBO = findSpecificTypeInParents<BinaryOperator>(S, C)) {
    if (PBO->isAssignmentOp())
      return PBO->getRHS();
  }

  // Variable initialization in a DeclStmt
  const DeclStmt *DS = dyn_cast<DeclStmt>(S);
  if (!DS)
    DS = findSpecificTypeInParents<DeclStmt>(S, C);

  if (DS) {
    MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
    for (const Decl *D : DS->decls()) {
      const auto *VD = dyn_cast<VarDecl>(D);
      if (!VD || !VD->hasInit())
        continue;
      const VarRegion *VR = MRMgr.getVarRegion(VD, C.getLocationContext());
      if (!VR)
        continue;
      if (VR->getBaseRegion() == LHSReg)
        return VD->getInit();
    }
  }

  return nullptr;
}

// Record in the program state that LHSReg is a "safe length" for an array found via sizeof() in RHS.
ProgramStateRef SAGenTestChecker::tryRecordArraySafeLen(ProgramStateRef State,
                                                        const Expr *RHS,
                                                        const MemRegion *LHSReg,
                                                        CheckerContext &C) const {
  if (!RHS || !LHSReg)
    return State;

  const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS);
  if (!UE || UE->getKind() != UETT_SizeOf)
    return State;

  const Expr *Arg = UE->getArgumentExpr();
  if (!Arg)
    return State;

  // Confirm it's an actual array
  llvm::APInt DummySize;
  if (!getArraySizeFromExpr(DummySize, Arg))
    return State;

  // Get the array region and normalize
  const MemRegion *ArrMR = getMemRegionFromExpr(Arg, C);
  if (!ArrMR)
    return State;
  ArrMR = ArrMR->getBaseRegion();
  if (!ArrMR)
    return State;

  return State->set<ArraySafeLenMap>(ArrMR, LHSReg);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Identify the LHS region being assigned to
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  ProgramStateRef State = C.getState();

  // Try to robustly get the RHS/init expression that leads to this bind.
  const Expr *RHS = recoverRHSForBind(S, LHSReg, C);
  if (!RHS) {
    // As a fallback, if S itself is a BinaryOperator we may still use it
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->isAssignmentOp())
        RHS = BO->getRHS();
    }
  }
  if (!RHS) {
    // No syntactic RHS we can analyze.
    return;
  }

  // If RHS contains sizeof(array), and we can resolve the array, record that this LHS is a safe len for that array.
  ProgramStateRef NewState = tryRecordArraySafeLen(State, RHS, LHSReg, C);

  // Weak heuristic kept: if RHS contains both min and sizeof, but we could not resolve array,
  // keep previous behavior to optionally mark the bound symbol as "bounded". This does not
  // affect the precise array mapping logic.
  if (NewState == State) {
    if (ExprHasName(RHS, "min", C) && ExprHasName(RHS, "sizeof", C)) {
      if (SymbolRef Sym = Val.getAsSymbol())
        NewState = NewState->add<BoundedLenSyms>(Sym);
    }
  }

  if (NewState != State)
    C.addTransition(NewState);
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
