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
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/ImmutableMap.h"
#include <algorithm>
#include <cctype>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the user prompt (assumed available)
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

// Track per-variable coarse upper bounds learned from assignments.
// Key: VarDecl*, Value: APSInt upper bound (unsigned).
namespace {
struct VarUpperBoundMap {};
// Track exact integer-constant assignments for variables within a function.
// Key: VarDecl*, Value: exact APSInt value assigned via literal/constant expression.
struct VarConstMap {};
}

namespace clang {
namespace ento {
template <>
struct ProgramStateTrait<VarUpperBoundMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const VarDecl *, llvm::APSInt>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<VarConstMap>
    : public ProgramStatePartialTrait<llvm::ImmutableMap<const VarDecl *, llvm::APSInt>> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};
} // namespace ento
} // namespace clang

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>,
        check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow shift widened to 64-bit", "Integer")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                   CheckerContext &C, StringRef Ctx) const;

  static const BinaryOperator *findShiftInTree(const Stmt *S);
  static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);

  static const Expr *peel(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static const BinaryOperator *asShift(const Stmt *S) {
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Shl)
        return BO;
    }
    return nullptr;
  }

  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  // Check if constant L and R guarantee that (L << R) fits within OpW bits (the
  // promoted width of the shift expression).
  static bool constantShiftFitsInWidth(const Expr *L, const Expr *R,
                                       unsigned OpW, CheckerContext &C) {
    llvm::APSInt LHSEval, RHSEval;
    if (!EvaluateExprToInt(LHSEval, L, C))
      return false;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;

    if (LHSEval.isSigned() && LHSEval.isNegative())
      return false;

    unsigned LBits = LHSEval.getActiveBits();
    uint64_t ShiftAmt = RHSEval.getZExtValue();
    if (LBits == 0)
      return true;
    return (uint64_t)LBits + ShiftAmt <= (uint64_t)OpW;
  }

  static bool isAnyLongType(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::Long) ||
           QT->isSpecificBuiltinType(BuiltinType::ULong);
  }

  static bool isFixed64Builtin(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::LongLong) ||
           QT->isSpecificBuiltinType(BuiltinType::ULongLong);
  }

  static bool calleeNameLooksLikeIOOrReg(StringRef Name) {
    llvm::SmallString<64> Lower(Name);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("read") || S.contains("write") || S.contains("peek") ||
           S.contains("poke") || S.contains("in") || S.contains("out") ||
           S.contains("io") || S.contains("reg");
  }

  static bool paramNameLooksLikeAddrOffset(const ParmVarDecl *P) {
    if (!P)
      return false;
    StringRef N = P->getName();
    if (N.empty())
      return false;

    llvm::SmallString<64> Lower(N);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("addr") || S.contains("address") || S.contains("offset") ||
           S.contains("ofs") || S.contains("reg") || S.contains("index") ||
           S.contains("port") || S.contains("bar");
  }

  static bool tryGetConstShiftAmount(const Expr *R, CheckerContext &C, uint64_t &Out) {
    llvm::APSInt RHSEval;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;
    Out = RHSEval.getZExtValue();
    return true;
  }

  static bool findCallParentAndArgIndex(const Expr *E, CheckerContext &C,
                                        const CallExpr *&OutCE, unsigned &OutIdx) {
    OutCE = findSpecificTypeInParents<CallExpr>(E, C);
    if (!OutCE)
      return false;

    const Expr *PE = peel(E);
    unsigned ArgCount = OutCE->getNumArgs();
    for (unsigned i = 0; i < ArgCount; ++i) {
      const Expr *AE = OutCE->getArg(i);
      if (peel(AE) == PE) {
        OutIdx = i;
        return true;
      }
    }
    return false;
  }

  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     QualType DestTy,
                                     CheckerContext &C,
                                     StringRef Ctx) {
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    // Keep argument-context heuristics.
    if (Ctx == "argument") {
      const CallExpr *CE = nullptr;
      unsigned ArgIdx = 0;
      if (findCallParentAndArgIndex(WholeExpr, C, CE, ArgIdx)) {
        const FunctionDecl *FD = CE->getDirectCallee();
        const ParmVarDecl *PVD = nullptr;
        if (FD && ArgIdx < FD->getNumParams())
          PVD = FD->getParamDecl(ArgIdx);

        if (isAnyLongType(DestTy))
          return true;

        if (PVD && paramNameLooksLikeAddrOffset(PVD))
          return true;

        if (FD) {
          if (const IdentifierInfo *ID = FD->getIdentifier()) {
            if (calleeNameLooksLikeIOOrReg(ID->getName()))
              return true;
          }
        }

        uint64_t K = 0;
        if (tryGetConstShiftAmount(Shl->getRHS(), C, K) && K <= 3)
          return true;
      }
    }

    return false;
  }

  // Extract a coarse upper bound from an assignment RHS by scanning integer literals.
  static bool extractUpperBoundLiteralFromRHS(const Expr *RHS, CheckerContext &C,
                                              llvm::APSInt &Out) {
    if (!RHS)
      return false;

    // Walk the subtree, find the maximum integer literal value.
    llvm::APSInt MaxVal(64, true); // unsigned
    bool Found = false;

    llvm::SmallVector<const Stmt *, 16> Worklist;
    Worklist.push_back(RHS);
    while (!Worklist.empty()) {
      const Stmt *Cur = Worklist.pop_back_val();
      if (!Cur) continue;

      if (const auto *IL = dyn_cast<IntegerLiteral>(Cur)) {
        llvm::APInt V = IL->getValue();
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *CharL = dyn_cast<CharacterLiteral>(Cur)) {
        llvm::APInt V(64, CharL->getValue());
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
        if (const Expr *SubE = UO->getSubExpr())
          Worklist.push_back(SubE);
      } else {
        for (const Stmt *Child : Cur->children())
          if (Child)
            Worklist.push_back(Child);
      }
    }

    if (Found) {
      Out = MaxVal;
      return true;
    }
    return false;
  }

  // Exact constant for variables from program state
  static bool getRecordedVarExactConst(const Expr *E, CheckerContext &C,
                                       llvm::APSInt &Out) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    ProgramStateRef State = C.getState();
    const llvm::APSInt *Stored = State->get<VarConstMap>(VD);
    if (!Stored)
      return false;
    Out = *Stored;
    return true;
  }

  static bool getRecordedVarUpperBound(const Expr *E, CheckerContext &C,
                                       llvm::APSInt &Out) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    ProgramStateRef State = C.getState();
    const llvm::APSInt *Stored = State->get<VarUpperBoundMap>(VD);
    if (!Stored)
      return false;
    Out = *Stored;
    return true;
  }

  // Compute an upper bound for an expression.
  static bool computeExprUpperBound(const Expr *E, CheckerContext &C,
                                    llvm::APSInt &Out) {
    if (!E)
      return false;
    E = peel(E);

    // Constant?
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      if (Val.isSigned() && Val.isNegative())
        return false; // not handling negative bounds here
      Out = Val.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Exact variable constant?
    if (getRecordedVarExactConst(E, C, Out)) {
      Out = Out.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Variable with recorded bound?
    if (getRecordedVarUpperBound(E, C, Out))
      return true;

    // Symbolic? Try constraint manager max.
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(E, C.getLocationContext());
    if (std::optional<nonloc::ConcreteInt> CI = SV.getAs<nonloc::ConcreteInt>()) {
      llvm::APSInt CIVal = CI->getValue();
      if (CIVal.isSigned() && CIVal.isNegative())
        return false;
      Out = CIVal.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }
    if (SymbolRef Sym = SV.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        llvm::APSInt M = *Max;
        if (M.isSigned() && M.isNegative())
          return false;
        Out = M.extOrTrunc(64);
        Out.setIsUnsigned(true);
        return true;
      }
    }

    // Simple additions
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Add) {
        llvm::APSInt LUB, RUB;
        if (computeExprUpperBound(BO->getLHS(), C, LUB) &&
            computeExprUpperBound(BO->getRHS(), C, RUB)) {
          unsigned BW = std::max(LUB.getBitWidth(), RUB.getBitWidth());
          llvm::APSInt L2 = LUB.extOrTrunc(BW);
          llvm::APSInt R2 = RUB.extOrTrunc(BW);
          L2.setIsUnsigned(true);
          R2.setIsUnsigned(true);
          Out = L2 + R2;
          Out.setIsUnsigned(true);
          return true;
        }
      }
      // Optional: handle LHS << RHS when both bounds known
      if (BO->getOpcode() == BO_Shl) {
        llvm::APSInt LUB, RUB;
        if (computeExprUpperBound(BO->getLHS(), C, LUB) &&
            computeExprUpperBound(BO->getRHS(), C, RUB)) {
          uint64_t Sh = RUB.getZExtValue();
          Sh = std::min<uint64_t>(Sh, 63);
          llvm::APSInt L2 = LUB.extOrTrunc(64);
          L2.setIsUnsigned(true);
          Out = llvm::APSInt(L2.getBitWidth(), 0);
          llvm::APInt Tmp = L2.getZExtValue();
          Tmp = Tmp.shl((unsigned)Sh);
          Out = llvm::APSInt(Tmp, true);
          return true;
        }
      }
    }

    return false;
  }

  // Compute maximum number of active bits an expression's value can have.
  static bool computeExprMaxActiveBits(const Expr *E, CheckerContext &C,
                                       unsigned &OutBits) {
    if (!E)
      return false;
    E = peel(E);

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      if (Val.isSigned() && Val.isNegative())
        return false;
      OutBits = Val.getActiveBits();
      return true;
    }

    llvm::APSInt UB;
    if (computeExprUpperBound(E, C, UB)) {
      OutBits = UB.getActiveBits();
      return true;
    }

    return false;
  }

  // Lightweight "forced-one" bits mask for an expression (64-bit).
  // Attempts to derive bits that are guaranteed 1, to get a minimum active-bits lower bound.
  static llvm::APInt computeForcedOneMask(const Expr *E, CheckerContext &C) {
    E = peel(E);
    llvm::APInt Zero(64, 0);

    if (!E)
      return Zero;

    // Integer constant
    if (const auto *IL = dyn_cast<IntegerLiteral>(E))
      return IL->getValue().zextOrTrunc(64);

    // Exact variable constant
    llvm::APSInt Exact;
    if (getRecordedVarExactConst(E, C, Exact))
      return Exact.extOrTrunc(64).getZExtValue();

    // Implicit/explicit casts, parens
    if (const auto *CE = dyn_cast<CastExpr>(E))
      return computeForcedOneMask(CE->getSubExpr(), C);

    if (const auto *PE = dyn_cast<ParenExpr>(E))
      return computeForcedOneMask(PE->getSubExpr(), C);

    // Binary ops
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      switch (BO->getOpcode()) {
      case BO_Or: {
        llvm::APInt LMask = computeForcedOneMask(BO->getLHS(), C);
        llvm::APInt RMask = computeForcedOneMask(BO->getRHS(), C);
        return LMask | RMask;
      }
      case BO_Shl: {
        llvm::APInt LMask = computeForcedOneMask(BO->getLHS(), C);
        // Need exact shift amount
        llvm::APSInt ShAmt;
        if (EvaluateExprToInt(ShAmt, BO->getRHS(), C) ||
            getRecordedVarExactConst(BO->getRHS(), C, ShAmt)) {
          uint64_t K = ShAmt.getZExtValue();
          if (K >= 64)
            return Zero;
          return LMask.shl((unsigned)K);
        }
        return Zero;
      }
      case BO_And: {
        llvm::APInt LMask = computeForcedOneMask(BO->getLHS(), C);
        llvm::APSInt RConst;
        if (EvaluateExprToInt(RConst, BO->getRHS(), C) ||
            getRecordedVarExactConst(BO->getRHS(), C, RConst)) {
          llvm::APInt RMask = RConst.extOrTrunc(64).getZExtValue();
          return LMask & RMask;
        }
        return Zero;
      }
      default:
        break;
      }
    }

    return Zero;
  }

  // Decide if the shift is provably safe within the operation width (e.g., 32-bit)
  // under computed upper bounds for L and R.
  static bool shiftSafeUnderUpperBounds(const Expr *L, const Expr *R,
                                        unsigned OpW, CheckerContext &C) {
    unsigned MaxLBits = 0;
    if (!computeExprMaxActiveBits(L, C, MaxLBits))
      return false;

    llvm::APSInt RMax;
    if (!computeExprUpperBound(R, C, RMax))
      return false;

    uint64_t ShiftMax = RMax.getZExtValue();

    if (MaxLBits == 0)
      return true;

    return (uint64_t)MaxLBits + ShiftMax <= (uint64_t)OpW;
  }

  // Small-constant-shift FP filter: suppress when RHS is a tiny constant (<= 5)
  // and we cannot prove risk from L.
  static bool smallConstantShiftBenign(const Expr *L, const Expr *R,
                                       unsigned OpW, CheckerContext &C) {
    llvm::APSInt RC;
    if (!(EvaluateExprToInt(RC, R, C)))
      return false;
    uint64_t K = RC.getZExtValue();
    const uint64_t SmallKThreshold = 5;
    if (K > SmallKThreshold)
      return false;

    // If L is constant, check exactly.
    llvm::APSInt LC;
    if (EvaluateExprToInt(LC, L, C)) {
      if (LC.isSigned() && LC.isNegative())
        return false;
      unsigned LBits = LC.getActiveBits();
      return (uint64_t)LBits + K <= (uint64_t)OpW;
    }

    // Use forced-one bits to get a lower bound on L's active bits.
    llvm::APInt Forced = computeForcedOneMask(L, C);
    unsigned MinLBits = Forced.getActiveBits();
    if (MinLBits == 0) {
      // With no evidence of large L, treat tiny shifts as benign to reduce FP.
      return true;
    }
    // If even the minimum L would overflow with K, do not suppress.
    return (uint64_t)MinLBits + K <= (uint64_t)OpW;
  }

  // Update VarConstMap for exact constant assignment
  static ProgramStateRef setOrClearVarConst(ProgramStateRef State,
                                            const VarDecl *VD,
                                            const Expr *RHS,
                                            CheckerContext &C) {
    llvm::APSInt Exact;
    if (EvaluateExprToInt(Exact, RHS, C)) {
      return State->set<VarConstMap>(VD, Exact);
    }
    // Not a constant: clear any existing entry.
    return State->remove<VarConstMap>(VD);
  }
};

const BinaryOperator *SAGenTestChecker::findShiftInTree(const Stmt *S) {
  if (!S)
    return nullptr;

  if (const BinaryOperator *B = asShift(S))
    return B;

  for (const Stmt *Child : S->children()) {
    if (const BinaryOperator *Res = findShiftInTree(Child))
      return Res;
  }
  return nullptr;
}

bool SAGenTestChecker::hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx) {
  if (!E)
    return false;

  if (const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParens())) {
    QualType ToTy = ECE->getType();
    if (ToTy->isIntegerType() && ACtx.getIntWidth(ToTy) >= 64)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (!Child)
      continue;
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasExplicitCastToWide64(CE, ACtx))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                                   CheckerContext &C, StringRef Ctx) const {
  if (!E)
    return;

  ASTContext &ACtx = C.getASTContext();

  if (!DestTy->isIntegerType())
    return;

  unsigned DestW = ACtx.getIntWidth(DestTy);
  if (DestW < 64)
    return;

  const BinaryOperator *Shl = findShiftInTree(E);
  if (!Shl || Shl->getOpcode() != BO_Shl)
    return;

  const Expr *L = Shl->getLHS();
  const Expr *R = Shl->getRHS();
  if (!L || !R)
    return;

  QualType ShlTy = Shl->getType();
  if (!ShlTy->isIntegerType())
    return;

  // Width of the shift expression after usual promotions.
  unsigned OpW = ACtx.getIntWidth(ShlTy);
  if (OpW >= 64)
    return; // Shift already performed in 64-bit, OK.

  if (!L->getType()->isIntegerType())
    return;

  if (hasExplicitCastToWide64(L, ACtx))
    return;

  if (isFalsePositiveContext(E, Shl, DestTy, C, Ctx))
    return;

  // If L and R are constants and fit within OpW, suppress.
  if (constantShiftFitsInWidth(L, R, OpW, C))
    return;

  // If using symbolic UB we can prove it fits within OpW, suppress.
  if (shiftSafeUnderUpperBounds(L, R, OpW, C))
    return;

  // Suppress tiny constant shifts unless we can prove risk.
  if (smallConstantShiftBenign(L, R, OpW, C))
    return;

  // Report
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Shift done in 32-bit, widened after; cast left operand to 64-bit before <<", N);
  Rpt->addRange(Shl->getSourceRange());
  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (VD->hasInit()) {
      QualType DestTy = VD->getType();
      const Expr *Init = VD->getInit();
      analyzeAndReportShiftToWide(Init, DestTy, C, "initialization");

      // Update VarConstMap if initializer is a constant.
      ProgramStateRef State = C.getState();
      ProgramStateRef NewState = setOrClearVarConst(State, VD, Init, C);

      // Also maintain coarse upper bound map
      llvm::APSInt BoundLit;
      if (extractUpperBoundLiteralFromRHS(Init, C, BoundLit)) {
        const llvm::APSInt *Cur = State->get<VarUpperBoundMap>(VD);
        llvm::APSInt NewBound = BoundLit;
        if (Cur && Cur->ugt(NewBound))
          NewBound = *Cur;
        NewState = NewState->set<VarUpperBoundMap>(VD, NewBound);
      }

      if (NewState != State)
        C.addTransition(NewState);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // First, perform shift-to-wide analysis for assignment context.
  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");

  // Update per-variable maps.
  const auto *DRE = dyn_cast<DeclRefExpr>(peel(LHS));
  if (!DRE)
    return;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  ProgramStateRef NewState = setOrClearVarConst(State, VD, RHS, C);

  llvm::APSInt BoundLit;
  if (extractUpperBoundLiteralFromRHS(RHS, C, BoundLit)) {
    const llvm::APSInt *Cur = NewState->get<VarUpperBoundMap>(VD);
    llvm::APSInt NewBound = BoundLit;
    if (Cur && Cur->ugt(NewBound))
      NewBound = *Cur;
    NewState = NewState->set<VarUpperBoundMap>(VD, NewBound);
  }

  if (NewState != State)
    C.addTransition(NewState);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  const StackFrameContext *SFC = C.getStackFrame();
  if (!SFC)
    return;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(SFC->getDecl());
  if (!FD)
    return;

  QualType DestTy = FD->getReturnType();
  analyzeAndReportShiftToWide(RetE, DestTy, C, "return");
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  unsigned NumArgs = Call.getNumArgs();
  unsigned NumParams = FD->getNumParams();
  unsigned N = std::min(NumArgs, NumParams);

  for (unsigned i = 0; i < N; ++i) {
    const ParmVarDecl *P = FD->getParamDecl(i);
    if (!P)
      continue;

    QualType DestTy = P->getType();
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    ASTContext &ACtx = C.getASTContext();
    if (!DestTy->isIntegerType() || ACtx.getIntWidth(DestTy) < 64)
      continue;

    analyzeAndReportShiftToWide(ArgE, DestTy, C, "argument");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit left shift widened to 64-bit after the shift (cast should be before <<)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 394 |           llvm::APInt Tmp = L2.getZExtValue();

	- Error Messages: conversion from ‘uint64_t’ {aka ‘long unsigned int’} to non-scalar type ‘llvm::APInt’ requested

- Error Line: 445 |       return Exact.extOrTrunc(64).getZExtValue();

	- Error Messages: could not convert ‘llvm::APSInt::extOrTrunc(uint32_t) const(64).llvm::APSInt::<anonymous>.llvm::APInt::getZExtValue()’ from ‘uint64_t’ {aka ‘long unsigned int’} to ‘llvm::APInt’

- Error Line: 480 |           llvm::APInt RMask = RConst.extOrTrunc(64).getZExtValue();

	- Error Messages: conversion from ‘uint64_t’ {aka ‘long unsigned int’} to non-scalar type ‘llvm::APInt’ requested



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
