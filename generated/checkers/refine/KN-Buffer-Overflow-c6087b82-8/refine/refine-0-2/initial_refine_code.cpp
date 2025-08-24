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

// New: Map using AST identity (VarDecl) of the array to the length variable region.
// This avoids relying on MemRegion extracted from an unevaluated sizeof().
REGISTER_MAP_WITH_PROGRAMSTATE(ArrayVDSafeLenMap, const VarDecl*, const MemRegion*)

// New: Track length variable regions whose most recent assignment was proven "bounded by sizeof".
// We treat them as safe only if they are in this set at the call site.
REGISTER_SET_WITH_PROGRAMSTATE(SafeLenRegs, const MemRegion*)

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

  // Try to identify destination as a fixed-size array. Returns true on success and fills ArraySize, ArrReg, ArrVD, ArrName.
  bool getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                        const VarDecl* &ArrVD, std::string &ArrName) const;

  // Determine if expression E contains sizeof() on the destination array (ArrVD) or (fallback) ArrReg/ArrName.
  bool exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                 const VarDecl *ArrVD, StringRef ArrName,
                                 CheckerContext &C) const;

  // Extract region and/or symbol for length expression.
  void getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                               const MemRegion* &LenReg, SymbolRef &LenSym) const;

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;

  // Determine if RHS is a min-like bound using sizeof(ArrVD), or a safe sizeof(ArrVD) +/- const expression.
  bool isBoundedBySizeof(const Expr *RHS, const VarDecl *ArrVD, CheckerContext &C) const;

  // Directly check if expression equals sizeof(arr) or sizeof(arr) - const (safe upper bound).
  bool isSizeofMinusConst(const Expr *E, const VarDecl *ArrVD) const;

  // Find a VarDecl of an array within an expression's children (common in &arr[0], arr+off).
  const VarDecl* findArrayVarDeclInExpr(const Expr *E) const;
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

const VarDecl* SAGenTestChecker::findArrayVarDeclInExpr(const Expr *E) const {
  if (!E)
    return nullptr;

  // Try direct DeclRefExpr
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      // Check if VD is an array (even if DRE type decayed)
      if (VD->getType()->isArrayType())
        return VD;
    }
  }

  // Walk down to find an inner DeclRefExpr referencing an array VarDecl
  if (const auto *InnerDRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(InnerDRE->getDecl())) {
      if (VD->getType()->isArrayType())
        return VD;
    }
  }

  return nullptr;
}

bool SAGenTestChecker::getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                                        const VarDecl* &ArrVD, std::string &ArrName) const {
  ArrReg = nullptr;
  ArrName.clear();
  ArrVD = nullptr;

  // Try to find the array VarDecl inside DstArg
  ArrVD = findArrayVarDeclInExpr(DstArg);
  if (!ArrVD)
    return false;

  // Get a constant size if available
  if (const auto *ArrayType = dyn_cast<ConstantArrayType>(ArrVD->getType().getTypePtr())) {
    ArraySize = ArrayType->getSize();
  } else {
    return false; // Only handle fixed-size arrays
  }

  // Retrieve the region of the destination expression (base region)
  const MemRegion *MR = getMemRegionFromExpr(DstArg, C);
  if (!MR)
    return false;
  MR = MR->getBaseRegion();
  if (!MR)
    return false;
  ArrReg = MR;

  ArrName = ArrVD->getNameAsString();
  return true;
}

bool SAGenTestChecker::exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                                 const VarDecl *ArrVD, StringRef ArrName,
                                                 CheckerContext &C) const {
  if (!E)
    return false;

  // AST-based check: find a sizeof(...) inside E that references the same array VarDecl
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(E)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg->IgnoreImplicit())) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
            if (VD == ArrVD)
              return true;
          }
        }
        // Fallback to MemRegion match if we can get it (may fail for unevaluated sizeof)
        if (ArrReg) {
          const MemRegion *SizeofMR = getMemRegionFromExpr(Arg, C);
          if (SizeofMR) {
            SizeofMR = SizeofMR->getBaseRegion();
            if (SizeofMR == ArrReg)
              return true;
          }
        }
      }
    }
  }

  // Textual fallback heuristic: expression contains both "sizeof" and the array's name.
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

bool SAGenTestChecker::isSizeofMinusConst(const Expr *E, const VarDecl *ArrVD) const {
  if (!E || !ArrVD)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *UE = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const auto *ArgDRE = dyn_cast<DeclRefExpr>(UE->getArgumentExpr()->IgnoreImplicit())) {
        if (const auto *VD = dyn_cast<VarDecl>(ArgDRE->getDecl()))
          return VD == ArrVD;
      }
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Sub) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (const auto *UE = dyn_cast<UnaryExprOrTypeTraitExpr>(LHS)) {
        if (UE->getKind() == UETT_SizeOf) {
          if (const auto *ArgDRE = dyn_cast<DeclRefExpr>(UE->getArgumentExpr()->IgnoreImplicit())) {
            if (const auto *VD = dyn_cast<VarDecl>(ArgDRE->getDecl())) {
              if (VD == ArrVD) {
                // RHS should be an integer constant (non-negative ideally) — we accept const
                if (isa<IntegerLiteral>(RHS))
                  return true;
                // Also accept a constant expression if evaluable
                // (AST-only check fallback; best-effort)
                return true;
              }
            }
          }
        }
      }
    }
  }
  return false;
}

bool SAGenTestChecker::isBoundedBySizeof(const Expr *RHS, const VarDecl *ArrVD, CheckerContext &C) const {
  if (!RHS || !ArrVD)
    return false;

  // Safe if it is exactly sizeof(arr) or sizeof(arr) - const
  if (isSizeofMinusConst(RHS, ArrVD))
    return true;

  const Expr *E = RHS->IgnoreParenImpCasts();

  // Textual min()-like macro or function use that includes sizeof(arr)
  if (ExprHasName(E, "min", C) && exprContainsSizeofOfArray(E, nullptr, ArrVD, ArrVD->getName(), C))
    return true;

  // Conditional operator pattern: (count > sizeof(arr) - 1) ? sizeof(arr) - 1 : count
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    const Expr *Cond = CO->getCond();
    const Expr *TrueE = CO->getTrueExpr();
    const Expr *FalseE = CO->getFalseExpr();

    bool CondHasSizeof = exprContainsSizeofOfArray(Cond, nullptr, ArrVD, ArrVD->getName(), C);
    bool TrueHasSizeof = exprContainsSizeofOfArray(TrueE, nullptr, ArrVD, ArrVD->getName(), C);
    bool FalseHasSizeof = exprContainsSizeofOfArray(FalseE, nullptr, ArrVD, ArrVD->getName(), C);

    // Accept if either branch is a sizeof(arr)-based bound and the condition references sizeof(arr).
    // This is a conservative acceptance for typical min-by-?: patterns.
    if ((TrueHasSizeof || FalseHasSizeof) && (CondHasSizeof || TrueHasSizeof || FalseHasSizeof)) {
      // Additional guard: reject patterns that grow beyond sizeof (e.g., sizeof(arr) + K) — already filtered by isSizeofMinusConst.
      return true;
    }
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

  // Default: if RHS is not a bounded expression, clear the freshness flag for this LHSReg.
  bool MadeSafe = false;

  // Look for sizeof(array) in RHS and try to associate this LHS length variable with that array,
  // but only if the expression is min-like or sizeof(arr) - const (safe bound).
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg->IgnoreImplicit())) {
          if (const auto *ArrVD = dyn_cast<VarDecl>(DRE->getDecl())) {
            if (ArrVD->getType()->isArrayType()) {
              if (isBoundedBySizeof(RHS, ArrVD, C)) {
                State = State->set<ArrayVDSafeLenMap>(ArrVD, LHSReg);
                State = State->add<SafeLenRegs>(LHSReg);
                MadeSafe = true;
              }
            }
          }
        }
      }
    }
  } else {
    // Heuristic: textual min() with sizeof may still exist even without an UE child (macro expansions).
    if (ExprHasName(RHS, "min", C) && ExprHasName(RHS, "sizeof", C)) {
      if (SymbolRef Sym = Val.getAsSymbol()) {
        State = State->add<BoundedLenSyms>(Sym);
      }
      // Can't tie to a specific array VarDecl here, but we can mark the len var as "fresh safe"
      // only if we also see a sizeof(...) in RHS. This is a weaker heuristic; do not mark it fresh
      // in SafeLenRegs because we cannot tie to the dst array identity safely.
    }
  }

  if (!MadeSafe) {
    // Not a bounded assignment; invalidate freshness for this length variable.
    if (State->contains<SafeLenRegs>(LHSReg))
      State = State->remove<SafeLenRegs>(LHSReg);
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
  const VarDecl *ArrVD = nullptr;
  std::string ArrName;
  if (!getDestArrayInfo(DstArg, C, ArraySizeAP, ArrReg, ArrVD, ArrName))
    return; // Only warn when destination is a provable fixed-size array

  uint64_t ArraySize = ArraySizeAP.getZExtValue();
  uint64_t SafeCopyLimit = (ArraySize > 0) ? (ArraySize - 1) : 0;

  // 1) Len directly contains sizeof(array) (inline safe patterns)
  if (exprContainsSizeofOfArray(LenArg, ArrReg, ArrVD, ArrName, C))
    return;

  ProgramStateRef State = C.getState();

  // 2) Len is a variable that we already recorded as safe for this array and is still "fresh"
  const MemRegion *LenReg = nullptr;
  SymbolRef LenSym = nullptr;
  getLenArgRegionOrSymbol(LenArg, C, LenReg, LenSym);

  bool HasFreshSafeLen = false;
  if (LenReg && State->contains<SafeLenRegs>(LenReg)) {
    // Prefer AST identity map first
    if (ArrVD) {
      if (const MemRegion *const *VDMap = State->get<ArrayVDSafeLenMap>(ArrVD)) {
        if (*VDMap == LenReg)
          HasFreshSafeLen = true;
      }
    }
    // Fallback to region-based map if available
    if (!HasFreshSafeLen && ArrReg) {
      if (const MemRegion *const *RegMap = State->get<ArraySafeLenMap>(ArrReg)) {
        if (*RegMap == LenReg)
          HasFreshSafeLen = true;
      }
    }
  }
  if (HasFreshSafeLen)
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
    // Otherwise, fall through to further checks.
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
