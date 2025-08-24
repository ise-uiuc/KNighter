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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map: for a given destination array region (key), remember the region of a "safe length" variable
// that was computed using sizeof(that array).
REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenMap, const MemRegion*, const MemRegion*)
// Optional fallback: symbols that we heuristically believe are bounded by some sizeof()
REGISTER_SET_WITH_PROGRAMSTATE(BoundedLenSyms, SymbolRef)

// New: Track by array VarDecl as key to avoid MemRegion shape/availability issues under sizeof().
REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenByVD, const VarDecl*, const MemRegion*)
// New: Reverse mapping to clear stale entries when the length variable gets reassigned.
REGISTER_MAP_WITH_PROGRAMSTATE(LenRegToArrayVD, const MemRegion*, const VarDecl*)

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

  // Try to identify destination as a fixed-size array. Returns true on success and fills ArraySize, ArrReg, ArrName, ArrVD.
  bool getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                        std::string &ArrName, const VarDecl* &ArrVD) const;

  // Determine if expression E contains sizeof() on the destination array (by VarDecl or region/name heuristic).
  bool exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                 StringRef ArrName, const VarDecl *ArrVD,
                                 CheckerContext &C) const;

  // Extract region and/or symbol for length expression.
  void getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                               const MemRegion* &LenReg, SymbolRef &LenSym) const;

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;

  // Return array VarDecl if expression references a fixed-size array variable.
  const VarDecl* getArrayVarDeclFromExpr(const Expr *E) const;

  // Get array size from VarDecl (ConstantArrayType).
  static bool getArraySizeFromVarDecl(llvm::APInt &ArraySize, const VarDecl *VD);

  // Build VarRegion for a given VarDecl.
  const MemRegion* getVarRegionForDecl(const VarDecl *VD, CheckerContext &C) const;

  // Clear stale mapping if LHS length variable previously associated with an array is now assigned a non-sizeof value.
  ProgramStateRef clearStaleLenVarMappings(ProgramStateRef State, const MemRegion *LHSReg,
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

const VarDecl* SAGenTestChecker::getArrayVarDeclFromExpr(const Expr *E) const {
  if (!E) return nullptr;
  const Expr *X = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(X)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (isa<ConstantArrayType>(VD->getType().getTypePtr()))
        return VD;
    }
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(X)) {
    return getArrayVarDeclFromExpr(ASE->getBase());
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(X)) {
    if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref)
      return getArrayVarDeclFromExpr(UO->getSubExpr());
  }
  return nullptr;
}

bool SAGenTestChecker::getArraySizeFromVarDecl(llvm::APInt &ArraySize, const VarDecl *VD) {
  if (!VD) return false;
  QualType QT = VD->getType();
  if (const auto *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
    ArraySize = ArrayType->getSize();
    return true;
  }
  return false;
}

const MemRegion* SAGenTestChecker::getVarRegionForDecl(const VarDecl *VD, CheckerContext &C) const {
  if (!VD) return nullptr;
  MemRegionManager &RM = C.getSValBuilder().getRegionManager();
  // VarRegion in current LocationContext is sufficient for identity comparison within this path.
  return RM.getVarRegion(VD, C.getLocationContext());
}

bool SAGenTestChecker::getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                                        std::string &ArrName, const VarDecl* &ArrVD) const {
  ArrReg = nullptr;
  ArrName.clear();
  ArrVD = nullptr;

  // First, try to identify the array VarDecl directly (more robust across sizeof()/decay).
  if (const VarDecl *VD = getArrayVarDeclFromExpr(DstArg)) {
    llvm::APInt SizeTmp;
    if (!getArraySizeFromVarDecl(SizeTmp, VD))
      return false;
    ArraySize = SizeTmp;
    ArrVD = VD;
    ArrName = VD->getNameAsString();
    // Build region from the VarDecl for stable identity.
    ArrReg = getVarRegionForDecl(VD, C);
    return true;
  }

  // Fallback to the original approach if VarDecl lookup failed.
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
    if (const auto *VD2 = dyn_cast<VarDecl>(DRE->getDecl())) {
      ArrName = VD2->getNameAsString();
      ArrVD = VD2;
    }
  }

  return true;
}

bool SAGenTestChecker::exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                                 StringRef ArrName, const VarDecl *ArrVD,
                                                 CheckerContext &C) const {
  if (!E)
    return false;

  // AST-based check: find a sizeof(...) inside E that references the same array
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(E)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        // Prefer matching by VarDecl for robustness in unevaluated contexts.
        if (const VarDecl *VD = getArrayVarDeclFromExpr(Arg)) {
          if (ArrVD && VD == ArrVD)
            return true;
        }
        // Fallback: region equivalence if available.
        if (ArrReg) {
          if (const MemRegion *SizeofMR = getMemRegionFromExpr(Arg, C)) {
            SizeofMR = SizeofMR->getBaseRegion();
            if (SizeofMR == ArrReg)
              return true;
          }
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

ProgramStateRef SAGenTestChecker::clearStaleLenVarMappings(ProgramStateRef State,
                                                           const MemRegion *LHSReg,
                                                           CheckerContext &C) const {
  if (!State || !LHSReg)
    return State;
  // If LHSReg was previously registered as "safe length" for some array, remove it.
  if (const VarDecl *const *PrevArrPtr = State->get<LenRegToArrayVD>(LHSReg)) {
    const VarDecl *PrevArr = *PrevArrPtr;
    State = State->remove<LenRegToArrayVD>(LHSReg);
    State = State->remove<ArraySafeLenByVD>(PrevArr);
    // Also remove region-based mapping if possible
    if (const MemRegion *ArrReg = getVarRegionForDecl(PrevArr, C)) {
      State = State->remove<ArraySafeLenMap>(ArrReg);
    }
  }
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

  // Look for sizeof(array) in RHS; if found, associate the array with this LHS length variable.
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        // Confirm it's an array decl ref (prefer VarDecl for stability)
        const VarDecl *ArrVD = getArrayVarDeclFromExpr(Arg);
        if (ArrVD) {
          // Build ArrReg if possible
          const MemRegion *ArrMR = getVarRegionForDecl(ArrVD, C);
          // Clear any stale association for this LHS first
          State = clearStaleLenVarMappings(State, LHSReg, C);
          // Record new associations (by VarDecl and region if available)
          State = State->set<ArraySafeLenByVD>(ArrVD, LHSReg);
          State = State->set<LenRegToArrayVD>(LHSReg, ArrVD);
          if (ArrMR)
            State = State->set<ArraySafeLenMap>(ArrMR, LHSReg);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // Weak heuristic: if RHS contains both min and sizeof, consider LHS symbol bounded
  if (ExprHasName(RHS, "min", C) && ExprHasName(RHS, "sizeof", C)) {
    if (SymbolRef Sym = Val.getAsSymbol()) {
      State = State->add<BoundedLenSyms>(Sym);
      C.addTransition(State);
      return;
    }
  }

  // If we got here, we didn't assign a sizeof()-based value. Clear stale mapping if any.
  State = clearStaleLenVarMappings(State, LHSReg, C);
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
  const VarDecl *ArrVD = nullptr;
  if (!getDestArrayInfo(DstArg, C, ArraySizeAP, ArrReg, ArrName, ArrVD))
    return; // Only warn when destination is a provable fixed-size array

  uint64_t ArraySize = ArraySizeAP.getZExtValue();
  uint64_t SafeCopyLimit = (ArraySize > 0) ? (ArraySize - 1) : 0;

  // 1) Len directly contains sizeof(array)
  if (exprContainsSizeofOfArray(LenArg, ArrReg, ArrName, ArrVD, C))
    return;

  ProgramStateRef State = C.getState();

  // 2) Len is a variable that we already recorded as safe for this array (by region or by VarDecl)
  const MemRegion *BoundRegForArray = nullptr;
  if (ArrReg) {
    if (const MemRegion *const *Ptr = State->get<ArraySafeLenMap>(ArrReg))
      BoundRegForArray = *Ptr;
  }
  const MemRegion *BoundRegForArrayByVD = nullptr;
  if (ArrVD) {
    if (const MemRegion *const *PtrVD = State->get<ArraySafeLenByVD>(ArrVD))
      BoundRegForArrayByVD = *PtrVD;
  }

  const MemRegion *LenReg = nullptr;
  SymbolRef LenSym = nullptr;
  getLenArgRegionOrSymbol(LenArg, C, LenReg, LenSym);

  if (LenReg && ((BoundRegForArray && (BoundRegForArray == LenReg)) ||
                 (BoundRegForArrayByVD && (BoundRegForArrayByVD == LenReg))))
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

  // 4) Infer maximal value for symbolic Len using constraints from prior branches
  if (LenSym) {
    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(LenSym, C)) {
      uint64_t MaxVal = MaxV->isSigned() ? (uint64_t)MaxV->getSExtValue()
                                         : MaxV->getZExtValue();
      if (MaxVal <= SafeCopyLimit)
        return; // safely bounded by sizeof(array) - 1
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
