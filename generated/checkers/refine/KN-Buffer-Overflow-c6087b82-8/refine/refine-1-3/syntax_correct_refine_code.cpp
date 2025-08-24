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
// New: For a given destination array region (key), remember the current SymbolRef of a "safe length".
REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenSymMap, const MemRegion*, SymbolRef)

namespace {

// Utility functions provided by the prompt.
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);

bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);

bool getStringSize(llvm::APInt &StringSize, const Expr *E);

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);

struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};

bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);

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

  // Determine if expression E contains sizeof() on the destination array.
  bool exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                 StringRef ArrName, CheckerContext &C) const;

  // Extract region and/or symbol for length expression.
  void getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                               const MemRegion* &LenReg, SymbolRef &LenSym) const;

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;

  // Helper to detect “safe” patterns to eliminate false positives.
  bool isLengthSafelyBoundedForArray(const Expr *LenArg,
                                     const MemRegion *ArrReg,
                                     StringRef ArrName,
                                     CheckerContext &C) const;
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

  // Heuristic textual fallback
  if (!ArrName.empty() && ExprHasName(E, "sizeof", C) && ExprHasName(E, ArrName, C))
    return true;

  return false;
}

void SAGenTestChecker::getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                                               const MemRegion* &LenReg, SymbolRef &LenSym) const {
  LenReg = nullptr;
  LenSym = nullptr;

  ProgramStateRef State = C.getState();

  // Try to get region directly from the expression (works for lvalues).
  const MemRegion *MR = getMemRegionFromExpr(LenArg, C);
  if (MR) {
    MR = MR->getBaseRegion();
    LenReg = MR;
  }

  // Fallback: for rvalue DeclRefExpr, reconstruct VarRegion via RegionManager.
  if (!LenReg) {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(LenArg->IgnoreImpCasts())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        const MemRegion *VarMR =
            C.getSValBuilder().getRegionManager().getVarRegion(VD, C.getLocationContext());
        if (VarMR) {
          LenReg = VarMR->getBaseRegion();
        }
      }
    }
  }

  // Also extract the symbol for the current value.
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

bool SAGenTestChecker::isLengthSafelyBoundedForArray(const Expr *LenArg,
                                                     const MemRegion *ArrReg,
                                                     StringRef ArrName,
                                                     CheckerContext &C) const {
  if (!LenArg || !ArrReg)
    return false;

  // Directly contains sizeof(array) in the length expression.
  if (exprContainsSizeofOfArray(LenArg, ArrReg, ArrName, C))
    return true;

  ProgramStateRef State = C.getState();

  // Region-based association: len variable computed from sizeof(array).
  const MemRegion *LenReg = nullptr;
  SymbolRef LenSym = nullptr;
  getLenArgRegionOrSymbol(LenArg, C, LenReg, LenSym);

  if (const MemRegion *const *BoundRegForArrayPtr = State->get<ArraySafeLenMap>(ArrReg)) {
    const MemRegion *BoundRegForArray = BoundRegForArrayPtr ? *BoundRegForArrayPtr : nullptr;
    if (BoundRegForArray && LenReg && (BoundRegForArray == LenReg))
      return true;
  }

  // Symbol-based association: the current symbol equals the “safe” symbol for this array.
  if (LenSym) {
    if (const SymbolRef *SafeSymPtr = State->get<ArraySafeLenSymMap>(ArrReg)) {
      SymbolRef SafeSym = *SafeSymPtr;
      if (SafeSym && SafeSym == LenSym)
        return true;
    }
    // Weak heuristic: a symbol we previously considered bounded by min(sizeof(...), ...)
    if (State->contains<BoundedLenSyms>(LenSym))
      return true;
  }

  return false;
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

  bool StateChanged = false;

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
              // Record array -> LHS var region association
              State = State->set<ArraySafeLenMap>(ArrMR, LHSReg);
              StateChanged = true;

              // Also record array -> LHS symbol association if available
              if (SymbolRef LSym = Val.getAsSymbol()) {
                State = State->set<ArraySafeLenSymMap>(ArrMR, LSym);
              }
            }
          }
        }
      }
    }
  } else {
    // Weak heuristic: if RHS contains both min and sizeof, consider LHS symbol bounded
    if (ExprHasName(RHS, "min", C) && ExprHasName(RHS, "sizeof", C)) {
      if (SymbolRef Sym = Val.getAsSymbol()) {
        State = State->add<BoundedLenSyms>(Sym);
        StateChanged = true;
      }
    }
  }

  if (StateChanged)
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

  // Eliminate cases bounded by sizeof(dest) at or before the call.
  if (isLengthSafelyBoundedForArray(LenArg, ArrReg, ArrName, C))
    return;

  ProgramStateRef State = C.getState();

  // Try to infer if Len is constant
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

  // Infer maximal value for symbolic Len
  SymbolRef LenSym = nullptr;
  {
    SVal SV = State->getSVal(LenArg, C.getLocationContext());
    LenSym = SV.getAsSymbol();
  }
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
