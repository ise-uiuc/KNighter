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

  enum UpperBoundOrigin {
    UBO_None = 0,
    UBO_Const = 1,
    UBO_ExactVar = 2,
    UBO_FromState = 4,
    UBO_FromVarUB = 8,
    UBO_FromExpr = 16
  };

  static bool tryEvalConstOrRecorded(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Out, UpperBoundOrigin &Origin) {
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      Out = Val;
      Origin = UBO_Const;
      return true;
    }
    if (getRecordedVarExactConst(E, C, Val)) {
      Out = Val;
      Origin = UBO_ExactVar;
      return true;
    }
    return false;
  }

  // Compute an upper bound for an expression. Also report where it comes from.
  static bool computeExprUpperBoundEx(const Expr *E, CheckerContext &C,
                                      llvm::APSInt &Out, UpperBoundOrigin &Origin) {
    if (!E)
      return false;
    E = peel(E);

    // Constants or recorded exact values
    if (tryEvalConstOrRecorded(E, C, Out, Origin)) {
      if (Out.isSigned() && Out.isNegative())
        return false;
      Out = Out.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Variable with recorded coarse upper bound?
    if (getRecordedVarUpperBound(E, C, Out)) {
      Origin = UBO_FromVarUB;
      Out = Out.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Symbolic? Try constraint manager max.
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(E, C.getLocationContext());
    if (std::optional<nonloc::ConcreteInt> CI = SV.getAs<nonloc::ConcreteInt>()) {
      llvm::APSInt CIVal = CI->getValue();
      if (CIVal.isSigned() && CIVal.isNegative())
        return false;
      Out = CIVal.extOrTrunc(64);
      Out.setIsUnsigned(true);
      Origin = UBO_Const;
      return true;
    }
    if (SymbolRef Sym = SV.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        llvm::APSInt M = *Max;
        if (M.isSigned() && M.isNegative())
          return false;
        Out = M.extOrTrunc(64);
        Out.setIsUnsigned(true);
        Origin = UBO_FromState;
        return true;
      }
    }

    // Structural handling
    if (const auto *CE = dyn_cast<CastExpr>(E)) {
      llvm::APSInt SubUB;
      UpperBoundOrigin SubO = UBO_None;
      if (computeExprUpperBoundEx(CE->getSubExpr(), C, SubUB, SubO)) {
        Out = SubUB;
        Origin = (UpperBoundOrigin)(SubO | UBO_FromExpr);
        return true;
      }
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      llvm::APSInt TUB, FUB;
      UpperBoundOrigin TO = UBO_None, FO = UBO_None;
      bool THave = computeExprUpperBoundEx(CO->getTrueExpr(), C, TUB, TO);
      bool FHave = computeExprUpperBoundEx(CO->getFalseExpr(), C, FUB, FO);
      if (THave && FHave) {
        unsigned BW = std::max(TUB.getBitWidth(), FUB.getBitWidth());
        llvm::APSInt T2 = TUB.extOrTrunc(BW);
        llvm::APSInt F2 = FUB.extOrTrunc(BW);
        T2.setIsUnsigned(true);
        F2.setIsUnsigned(true);
        Out = (T2 > F2) ? T2 : F2;
        Origin = (UpperBoundOrigin)(TO | FO | UBO_FromExpr);
        return true;
      }
      if (THave) {
        Out = TUB;
        Origin = (UpperBoundOrigin)(TO | UBO_FromExpr);
        return true;
      }
      if (FHave) {
        Out = FUB;
        Origin = (UpperBoundOrigin)(FO | UBO_FromExpr);
        return true;
      }
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      llvm::APSInt LUB, RUB;
      UpperBoundOrigin LO = UBO_None, RO = UBO_None;

      auto combineUBits = [&](llvm::APSInt &A, llvm::APSInt &B) -> unsigned {
        llvm::APSInt A2 = A.extOrTrunc(64); A2.setIsUnsigned(true);
        llvm::APSInt B2 = B.extOrTrunc(64); B2.setIsUnsigned(true);
        return std::max(A2.getBitWidth(), B2.getBitWidth());
      };

      switch (BO->getOpcode()) {
      case BO_Add:
      case BO_Sub:
      case BO_Mul:
      case BO_Div:
      case BO_Rem:
        // Fallback: try generic UB on both sides, add for Add/Sub as a safe over-approx.
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          unsigned BW = std::max(LUB.getBitWidth(), RUB.getBitWidth());
          llvm::APSInt L2 = LUB.extOrTrunc(BW); L2.setIsUnsigned(true);
          llvm::APSInt R2 = RUB.extOrTrunc(BW); R2.setIsUnsigned(true);
          if (BO->getOpcode() == BO_Add || BO->getOpcode() == BO_Sub) {
            Out = L2 + R2; // Safe upper bound
          } else if (BO->getOpcode() == BO_Mul) {
            llvm::APInt Tmp = static_cast<const llvm::APInt &>(L2);
            Tmp = Tmp.zextOrTrunc(64);
            Tmp = Tmp * static_cast<const llvm::APInt &>(R2);
            Out = llvm::APSInt(Tmp, true);
          } else {
            // For Div/Rem, upper bound cannot exceed LHS upper bound.
            Out = L2;
          }
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;

      case BO_Or:
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          llvm::APInt LA = static_cast<const llvm::APInt &>(LUB.extOrTrunc(64));
          llvm::APInt RA = static_cast<const llvm::APInt &>(RUB.extOrTrunc(64));
          Out = llvm::APSInt(LA | RA, true);
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;

      case BO_Xor:
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          llvm::APInt LA = static_cast<const llvm::APInt &>(LUB.extOrTrunc(64));
          llvm::APInt RA = static_cast<const llvm::APInt &>(RUB.extOrTrunc(64));
          // Upper bound of XOR is safely bounded by OR of UB's.
          Out = llvm::APSInt(LA | RA, true);
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;

      case BO_And: {
        bool LH = computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO);
        bool RH = computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO);
        if (LH && RH) {
          // A & B <= min(UB(A), UB(B))
          llvm::APSInt L2 = LUB.extOrTrunc(64); L2.setIsUnsigned(true);
          llvm::APSInt R2 = RUB.extOrTrunc(64); R2.setIsUnsigned(true);
          Out = (L2 < R2) ? L2 : R2;
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        // Better: if one side is constant, result UB is <= that constant
        llvm::APSInt ConstSide;
        UpperBoundOrigin OO = UBO_None;
        if (tryEvalConstOrRecorded(BO->getLHS(), C, ConstSide, OO)) {
          Out = ConstSide.extOrTrunc(64);
          Out.setIsUnsigned(true);
          Origin = (UpperBoundOrigin)(OO | UBO_FromExpr);
          return true;
        }
        if (tryEvalConstOrRecorded(BO->getRHS(), C, ConstSide, OO)) {
          Out = ConstSide.extOrTrunc(64);
          Out.setIsUnsigned(true);
          Origin = (UpperBoundOrigin)(OO | UBO_FromExpr);
          return true;
        }
        break;
      }

      case BO_Shl: {
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO) &&
            computeExprUpperBoundEx(BO->getRHS(), C, RUB, RO)) {
          uint64_t Sh = RUB.getZExtValue();
          Sh = std::min<uint64_t>(Sh, 63);
          llvm::APSInt L2 = LUB.extOrTrunc(64);
          L2.setIsUnsigned(true);
          llvm::APInt Tmp = static_cast<const llvm::APInt &>(L2);
          Tmp = Tmp.shl((unsigned)Sh);
          Out = llvm::APSInt(Tmp, true);
          Origin = (UpperBoundOrigin)(LO | RO | UBO_FromExpr);
          return true;
        }
        break;
      }

      case BO_Shr: {
        if (computeExprUpperBoundEx(BO->getLHS(), C, LUB, LO)) {
          // Use smallest shift (best-case for maximizing the result).
          llvm::APSInt ShiftC;
          UpperBoundOrigin SO = UBO_None;
          uint64_t MinShift = 0;
          if (tryEvalConstOrRecorded(BO->getRHS(), C, ShiftC, SO)) {
            MinShift = std::min<uint64_t>(ShiftC.getZExtValue(), 63);
          } else {
            // If we can get an upper bound for shift, min is 0.
            // So UB(result) <= UB(LHS)
            MinShift = 0;
          }
          llvm::APSInt L2 = LUB.extOrTrunc(64);
          L2.setIsUnsigned(true);
          llvm::APInt Tmp = static_cast<const llvm::APInt &>(L2);
          if (MinShift > 0)
            Tmp = Tmp.lshr((unsigned)MinShift);
          Out = llvm::APSInt(Tmp, true);
          Origin = (UpperBoundOrigin)(LO | UBO_FromExpr);
          return true;
        }
        break;
      }

      default:
        break;
      }
    }

    return false;
  }

  static bool computeExprUpperBound(const Expr *E, CheckerContext &C,
                                    llvm::APSInt &Out) {
    UpperBoundOrigin Ign = UBO_None;
    return computeExprUpperBoundEx(E, C, Out, Ign);
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
    if (getRecordedVarExactConst(E, C, Exact)) {
      llvm::APSInt E2 = Exact.extOrTrunc(64);
      E2.setIsUnsigned(true);
      return static_cast<const llvm::APInt &>(E2);
    }

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
          llvm::APSInt RC2 = RConst.extOrTrunc(64);
          RC2.setIsUnsigned(true);
          llvm::APInt RMask = static_cast<const llvm::APInt &>(RC2);
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

  static bool isFunctionParamExpr(const Expr *E) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    return isa<ParmVarDecl>(DRE->getDecl());
  }

  static bool isSmallLiteralLE(const Expr *E, unsigned Limit, CheckerContext &C, uint64_t &ValOut) {
    llvm::APSInt LC;
    if (!EvaluateExprToInt(LC, E, C))
      return false;
    if (LC.isSigned() && LC.isNegative())
      return false;
    uint64_t V = LC.getZExtValue();
    if (V <= Limit) {
      ValOut = V;
      return true;
    }
    return false;
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

  // Compute provable risk using upper bounds.
  // 1) Compute maximum active bits for L.
  unsigned MaxLBits = 0;
  bool HaveLBits = computeExprMaxActiveBits(L, C, MaxLBits);

  // 2) Compute an upper bound for shift amount and its origin.
  llvm::APSInt RMax;
  UpperBoundOrigin ROrigin = UBO_None;
  bool HaveRMax = computeExprUpperBoundEx(R, C, RMax, ROrigin);

  // Additional FP filter: if the only knowledge about RHS is the generic
  // "shift less than OpW" constraint (common for preventing UB), and LHS is a tiny
  // literal (<= 8) and RHS is a function parameter, treat as benign.
  if (HaveRMax && ROrigin == UBO_FromState && RMax.getZExtValue() == (OpW - 1)) {
    uint64_t TinyV = 0;
    if (isFunctionParamExpr(R) && isSmallLiteralLE(L, 8, C, TinyV)) {
      return; // suppress this likely benign test pattern, e.g., 3 << order
    }
  }

  // If we can prove it's safe under upper bounds, suppress.
  if (HaveLBits && HaveRMax) {
    uint64_t ShiftMax = RMax.getZExtValue();
    if (MaxLBits == 0 || (uint64_t)MaxLBits + ShiftMax <= (uint64_t)OpW)
      return;
  } else {
    // If we cannot prove risk (lack of bounds), be conservative and do not warn.
    // This avoids FPs where shift amount is effectively bounded but not modeled.
    return;
  }

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
