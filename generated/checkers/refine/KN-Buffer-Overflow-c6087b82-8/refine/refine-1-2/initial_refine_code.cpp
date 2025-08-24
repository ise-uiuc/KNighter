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
// Map: for a given destination array region (key), remember the exact SymbolRef for the
// safely bounded length value (produced by an expression that includes sizeof(array)).
REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenSymMap, const MemRegion*, SymbolRef)

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

  // Extract region and/or symbol for length expression, robustly even when used as rvalue.
  void getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                               const MemRegion* &LenReg, SymbolRef &LenSym) const;

  // Get VarRegion for a variable referenced by a DeclRefExpr, independent of rvalue/lvalue context.
  const MemRegion *getVarRegionFromDeclRef(const Expr *E, CheckerContext &C) const;

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;
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
  if (!MR) {
    // As a fallback, try to get it from the DeclRefExpr path.
    MR = getVarRegionFromDeclRef(DstArg, C);
  }
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
        if (!SizeofMR) {
          SizeofMR = getVarRegionFromDeclRef(Arg, C);
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

const MemRegion *SAGenTestChecker::getVarRegionFromDeclRef(const Expr *E, CheckerContext &C) const {
  const Expr *IE = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!IE)
    return nullptr;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(IE)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      SVal LVal = C.getSValBuilder().getLValue(VD, C.getLocationContext());
      if (const MemRegion *MR = LVal.getAsRegion())
        return MR->getBaseRegion();
    }
  }
  return nullptr;
}

void SAGenTestChecker::getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                                               const MemRegion* &LenReg, SymbolRef &LenSym) const {
  LenReg = nullptr;
  LenSym = nullptr;

  ProgramStateRef State = C.getState();

  // Try to get region via standard helper first.
  const MemRegion *MR = getMemRegionFromExpr(LenArg, C);
  if (!MR) {
    // If LenArg is a DeclRefExpr used as an rvalue, the above often fails.
    MR = getVarRegionFromDeclRef(LenArg, C);
  }
  if (MR) {
    MR = MR->getBaseRegion();
    LenReg = MR;
  }

  // Try to get symbol (value being passed)
  SVal SV = State->getSVal(LenArg, C.getLocationContext());
  if (SymbolRef S = SV.getAsSymbol())
    LenSym = S;
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

  // Look for sizeof(array) in RHS; if found, associate the array with this LHS length variable,
  // and also record the specific symbolic value that represents the bounded length.
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        // Confirm it's an array decl ref
        llvm::APInt DummySize;
        if (getArraySizeFromExpr(DummySize, Arg)) {
          const MemRegion *ArrMR = getMemRegionFromExpr(Arg, C);
          if (!ArrMR)
            ArrMR = getVarRegionFromDeclRef(Arg, C);
          if (ArrMR) {
            ArrMR = ArrMR->getBaseRegion();
            if (ArrMR) {
              State = State->set<ArraySafeLenMap>(ArrMR, LHSReg);
              if (SymbolRef Sym = Val.getAsSymbol()) {
                State = State->set<ArraySafeLenSymMap>(ArrMR, Sym);
                // Heuristic convenience: also mark symbol as bounded.
                State = State->add<BoundedLenSyms>(Sym);
              }
            }
          }
        }
      }
    }
  } else {
    // Weak heuristic: if RHS contains both min and sizeof, consider symbol bounded
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

  // 1) Len directly contains sizeof(array) (safe)
  if (exprContainsSizeofOfArray(LenArg, ArrReg, ArrName, C))
    return;

  ProgramStateRef State = C.getState();

  // Extract current region and symbol of LenArg
  const MemRegion *LenReg = nullptr;
  SymbolRef LenSym = nullptr;
  getLenArgRegionOrSymbol(LenArg, C, LenReg, LenSym);

  // 2) If the current length symbol equals the previously recorded "safe" symbol for this array, it's safe.
  if (const SymbolRef *SafeSymPtr = State->get<ArraySafeLenSymMap>(ArrReg)) {
    if (*SafeSymPtr && LenSym && *SafeSymPtr == LenSym)
      return;
  }

  // Keep previous heuristic: if we heuristically said the symbol is bounded, accept it.
  if (LenSym && State->contains<BoundedLenSyms>(LenSym))
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
    // Otherwise, continue checks.
  }

  // 4) Infer maximal value for symbolic Len from constraints
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
