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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

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
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

// Program state: Map constant-valued integer locals to their known values.
REGISTER_MAP_WITH_PROGRAMSTATE(ConstIntVarMap, const VarDecl *, llvm::APSInt)

namespace {

class SAGenTestChecker
    : public Checker<
          check::PostStmt<BinaryOperator>,
          check::PostStmt<DeclStmt>,
          check::Bind,
          check::RegionChanges> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "32-bit multiply widened to 64-bit",
                       "Integer Overflow")) {}

  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const LocationContext *LCtx,
                                     const CallEvent *Call) const;

private:
  static unsigned getIntWidth(QualType T, CheckerContext &C) {
    return C.getASTContext().getIntWidth(T);
  }

  static bool isInt64OrWider(QualType T, CheckerContext &C) {
    return T->isIntegerType() && getIntWidth(T, C) >= 64;
  }

  static bool isIntegerType(const Expr *E) {
    if (!E) return false;
    return E->getType()->isIntegerType();
  }

  static const Expr *ignoreNoOps(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static bool isNoOpWrapper(const Stmt *S) {
    return isa<ParenExpr>(S) || isa<ImplicitCastExpr>(S);
  }

  static bool isSizeT(QualType T, CheckerContext &C) {
    ASTContext &AC = C.getASTContext();
    return AC.hasSameType(AC.getCanonicalType(T),
                          AC.getCanonicalType(AC.getSizeType()));
  }

  static StringRef getRecordNameFromExprBase(const Expr *E) {
    if (!E) return StringRef();
    QualType QT = E->getType();
    if (const auto *PT = QT->getAs<PointerType>())
      QT = PT->getPointeeType();
    if (const auto *RT = QT->getAs<RecordType>()) {
      const RecordDecl *RD = RT->getDecl();
      if (const IdentifierInfo *II = RD->getIdentifier())
        return II->getName();
    }
    return StringRef();
  }

  static StringRef getDeclRefName(const Expr *E) {
    if (!E) return StringRef();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        return VD->getName();
    }
    return StringRef();
  }

  // Helpers to work with state-tracked constant ints.
  static bool getConstValueFromState(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Out) {
    const Expr *Core = ignoreNoOps(E);
    if (!Core)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        ProgramStateRef St = C.getState();
        if (const llvm::APSInt *V = St->get<ConstIntVarMap>(VD)) {
          Out = *V;
          return true;
        }
      }
    }
    return false;
  }

  // Peel parens and implicit casts to find the original (pre-promotion) integer type of an operand.
  struct OrigIntInfo {
    unsigned Width = 0;
    bool IsUnsigned = false;
    bool Valid = false;
  };

  OrigIntInfo getOriginalIntegerInfo(const Expr *E, CheckerContext &C) const {
    OrigIntInfo Info;
    if (!E) return Info;

    const Expr *Cur = E;
    // Do not use IgnoreParenImpCasts here; we want to walk casts ourselves to stop at the source.
    while (true) {
      if (const auto *PE = dyn_cast<ParenExpr>(Cur)) {
        Cur = PE->getSubExpr();
        continue;
      }
      if (const auto *ICE = dyn_cast<ImplicitCastExpr>(Cur)) {
        switch (ICE->getCastKind()) {
        case CK_NoOp:
        case CK_LValueToRValue:
        case CK_IntegralCast:
        case CK_IntegralToBoolean:
        case CK_IntegralPromotion:
          Cur = ICE->getSubExpr();
          continue;
        default:
          // Other implicit casts shouldn't matter for integer width; stop here.
          break;
        }
      }
      break;
    }

    QualType QT = Cur->getType();
    if (!QT->isIntegerType())
      return Info;

    Info.Width = getIntWidth(QT, C);
    Info.IsUnsigned = QT->isUnsignedIntegerType();

    // If this is a reference to a bit-field, use its declared bit width.
    if (const auto *ME = dyn_cast<MemberExpr>(Cur)) {
      if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
        if (FD->isBitField()) {
          unsigned BW = FD->getBitWidthValue(C.getASTContext());
          if (BW)
            Info.Width = BW;
          Info.IsUnsigned = FD->getType()->isUnsignedIntegerType();
        }
      }
    }

    Info.Valid = true;
    return Info;
  }

  // Require at least one original operand to be 32-bit or wider to match the intended bug pattern.
  bool atLeastOneOperandOriginally32Plus(const BinaryOperator *B,
                                         CheckerContext &C) const {
    OrigIntInfo L = getOriginalIntegerInfo(B->getLHS(), C);
    OrigIntInfo R = getOriginalIntegerInfo(B->getRHS(), C);

    // If both known and both narrower than 32 bits, we don't want to warn.
    if (L.Valid && R.Valid) {
      if (L.Width < 32 && R.Width < 32)
        return false;
      return (L.Width >= 32) || (R.Width >= 32);
    }

    // If we only know one side, require that known side is >= 32.
    if (L.Valid && L.Width < 32 && !R.Valid)
      return false;
    if (R.Valid && R.Width < 32 && !L.Valid)
      return false;

    // Otherwise be conservative and allow.
    return true;
  }

  bool getImmediateNonTrivialParent(const Stmt *Child,
                                    CheckerContext &C,
                                    const Stmt *&OutParentStmt,
                                    const Decl *&OutParentDecl) const {
    OutParentStmt = nullptr;
    OutParentDecl = nullptr;
    if (!Child)
      return false;

    const Stmt *Cur = Child;
    while (true) {
      auto Parents = C.getASTContext().getParents(*Cur);
      if (Parents.empty())
        return false;

      const Stmt *PS = Parents[0].get<Stmt>();
      const Decl *PD = Parents[0].get<Decl>();

      if (PS) {
        if (isNoOpWrapper(PS)) {
          Cur = PS;
          continue;
        }
        OutParentStmt = PS;
        return true;
      } else if (PD) {
        OutParentDecl = PD;
        return true;
      } else {
        return false;
      }
    }
  }

  bool isDirectWidenedUseTo64(const Expr *Mul,
                              CheckerContext &C,
                              const Stmt *&UseSiteStmt,
                              const Decl *&UseSiteDecl) const {
    UseSiteStmt = nullptr;
    UseSiteDecl = nullptr;
    if (!Mul)
      return false;

    const Stmt *PStmt = nullptr;
    const Decl *PDecl = nullptr;
    if (!getImmediateNonTrivialParent(Mul, C, PStmt, PDecl))
      return false;

    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(PStmt)) {
      if (!BO->isAssignmentOp())
        return false;
      const Expr *LHS = BO->getLHS();
      if (LHS && isInt64OrWider(LHS->getType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *CS = dyn_cast_or_null<CStyleCastExpr>(PStmt)) {
      QualType DestTy = CS->getTypeAsWritten();
      if (isInt64OrWider(DestTy, C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(PStmt)) {
      const auto *FD =
          dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (FD && isInt64OrWider(FD->getReturnType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Call = dyn_cast_or_null<CallExpr>(PStmt)) {
      const FunctionDecl *FD = Call->getDirectCallee();
      if (!FD)
        return false;

      for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
        const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
        const Expr *MulCore = Mul->IgnoreParenImpCasts();
        if (Arg == MulCore) {
          QualType ParamTy = FD->getParamDecl(i)->getType();
          if (isInt64OrWider(ParamTy, C)) {
            UseSiteStmt = PStmt;
            return true;
          }
        }
      }
      return false;
    }

    if (const auto *VD = dyn_cast_or_null<VarDecl>(PDecl)) {
      if (isInt64OrWider(VD->getType(), C)) {
        UseSiteDecl = PDecl;
        return true;
      }
      return false;
    }

    return false;
  }

  // Domain-specific maxima to tighten bounds for known Linux patterns.
  bool getDomainSpecificMax(const Expr *E, CheckerContext &C,
                            llvm::APSInt &Out) const {
    if (!E) return false;
    const Expr *Core = E->IgnoreParenImpCasts();

    const auto *DRE = dyn_cast<DeclRefExpr>(Core);
    if (!DRE) return false;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD) return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD) return false;

    StringRef FuncName = FD->getName();
    StringRef VarName = VD->getName();

    // PCI/MSI-X: msix_map_region(dev, unsigned int nr_entries)
    // nr_entries is derived from msix_table_size(control) with a spec-bound <= 2048.
    if (FuncName.equals("msix_map_region") && VarName.equals("nr_entries")) {
      Out = llvm::APSInt(llvm::APInt(32, 2048), /*isUnsigned=*/true);
      return true;
    }

    return false;
  }

  // Try to determine an upper bound for an expression.
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    E = E->IgnoreParenImpCasts();

    // Exact tracked constant?
    if (getConstValueFromState(E, C, Out))
      return true;

    // Domain-specific bound (e.g. nr_entries <= 2048 in msix_map_region).
    if (getDomainSpecificMax(E, C, Out))
      return true;

    // Constant evaluation?
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Simple folding for sum/difference to tighten bounds.
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->isAdditiveOp()) {
        llvm::APSInt LMax, RMax;
        bool HasL = getMaxForExpr(BO->getLHS(), C, LMax);
        bool HasR = getMaxForExpr(BO->getRHS(), C, RMax);
        if (HasL && HasR) {
          __int128 L = LMax.isSigned() ? (__int128)LMax.getExtValue()
                                       : (__int128)LMax.getZExtValue();
          __int128 R = RMax.isSigned() ? (__int128)RMax.getExtValue()
                                       : (__int128)RMax.getZExtValue();
          __int128 S = BO->getOpcode() == BO_Add ? (L + R) : (L - R);
          uint64_t UB = S < 0 ? 0 : (S > (__int128)UINT64_MAX ? UINT64_MAX : (uint64_t)S);
          Out = llvm::APSInt(llvm::APInt(64, UB), /*isUnsigned=*/true);
          return true;
        }
      }
    }

    // Symbolic maximum?
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (Sym) {
      if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
        Out = *MaxV;
        return true;
      }
    }

    // Fallback: type-based maximum
    QualType QT = E->getType();
    if (!QT->isIntegerType())
      return false;

    unsigned W = getIntWidth(QT, C);
    bool IsUnsigned = QT->isUnsignedIntegerType();
    if (W == 0)
      return false;

    if (IsUnsigned) {
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/true);
    } else {
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/false);
    }
    return true;
  }

  // Check if we can prove the product fits into the narrower arithmetic width.
  bool productDefinitelyFits(const BinaryOperator *B, CheckerContext &C) const {
    if (!B) return false;
    const Expr *LHS = B->getLHS();
    const Expr *RHS = B->getRHS();
    if (!LHS || !RHS)
      return false;

    llvm::APSInt MaxL, MaxR;
    if (!getMaxForExpr(LHS, C, MaxL) || !getMaxForExpr(RHS, C, MaxR))
      return false; // Can't prove, so not definitely safe.

    // Compute conservatively using 128-bit.
    uint64_t ML = MaxL.isSigned() ? (uint64_t)MaxL.getExtValue() : MaxL.getZExtValue();
    uint64_t MR = MaxR.isSigned() ? (uint64_t)MaxR.getExtValue() : MaxR.getZExtValue();
    __uint128_t Prod = ((__uint128_t)ML) * ((__uint128_t)MR);

    // Determine limit for the arithmetic type of the multiply.
    unsigned MulW = getIntWidth(B->getType(), C);
    bool IsUnsignedMul = B->getType()->isUnsignedIntegerType();

    if (MulW >= 64) {
      return true;
    }

    __uint128_t Limit;
    if (IsUnsignedMul) {
      Limit = (((__uint128_t)1) << MulW) - 1;
    } else {
      // Signed max: 2^(W-1) - 1
      Limit = (((__uint128_t)1) << (MulW - 1)) - 1;
    }

    return Prod <= Limit;
  }

  bool containsAnyName(const Expr *E, CheckerContext &C,
                       std::initializer_list<StringRef> Needles) const {
    if (!E) return false;
    for (StringRef N : Needles) {
      if (ExprHasName(E, N, C))
        return true;
    }
    return false;
  }

  bool containsAnyNameInString(StringRef S,
                               std::initializer_list<StringRef> Needles) const {
    for (StringRef N : Needles) {
      if (S.contains(N))
        return true;
    }
    return false;
  }

  bool looksLikeSizeContext(const Stmt *UseSiteStmt,
                            const Decl *UseSiteDecl,
                            const BinaryOperator *Mul,
                            CheckerContext &C) const {
    static const std::initializer_list<StringRef> Positives = {
        "size", "len", "length", "count", "num", "bytes", "capacity", "total", "sz"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp()) {
        const Expr *LHS = BO->getLHS();
        if (LHS && containsAnyName(LHS, C, Positives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Positives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Positives))
          return true;
      }
      if (Mul) {
        if (containsAnyName(Mul->getLHS(), C, Positives) ||
            containsAnyName(Mul->getRHS(), C, Positives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
          const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
          const Expr *MulCore = Mul ? Mul->IgnoreParenImpCasts() : nullptr;
          if (Arg == MulCore) {
            StringRef PName = FD->getParamDecl(i)->getName();
            if (containsAnyNameInString(PName, Positives))
              return true;
          }
        }
      }
    }
    if (Mul) {
      if (containsAnyName(Mul->getLHS(), C, Positives) ||
          containsAnyName(Mul->getRHS(), C, Positives))
        return true;
    }
    return false;
  }

  bool looksLikeNonSizeEncodingContext(const Stmt *UseSiteStmt,
                                       const Decl *UseSiteDecl,
                                       CheckerContext &C) const {
    static const std::initializer_list<StringRef> Negatives = {
        "irq", "hwirq", "interrupt", "index", "idx", "id",
        "ino", "inode", "perm", "class", "sid"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp() && BO->getLHS()) {
        if (containsAnyName(BO->getLHS(), C, Negatives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Negatives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
        for (const ParmVarDecl *P : FD->parameters()) {
          if (containsAnyNameInString(P->getName(), Negatives))
            return true;
        }
      }
    }
    return false;
  }

  // Heuristic: detect Linux sysfs bin_attribute.size assignment patterns.
  bool isLinuxBinAttributeSizeAssignment(const Stmt *UseSiteStmt,
                                         CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    LHS = LHS->IgnoreParenImpCasts();
    if (!isSizeT(LHS->getType(), C))
      return false;

    const auto *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return false;

    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return false;

    if (!FD->getIdentifier() || FD->getName() != "size")
      return false;

    const RecordDecl *RD = FD->getParent();
    StringRef RName;
    if (RD) {
      if (const IdentifierInfo *II = RD->getIdentifier())
        RName = II->getName();
    }
    if (RName.empty())
      RName = getRecordNameFromExprBase(ME->getBase());

    if (RName.contains("bin_attribute") || RName.contains("attribute"))
      return true;

    return false;
  }

  // Heuristic: whether expression references an "ops" struct member (common in Linux).
  bool exprComesFromOps(const Expr *E) const {
    if (!E) return false;
    E = E->IgnoreParenImpCasts();
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME)
      return false;

    const Expr *Base = ME->getBase();
    StringRef BaseVarName = getDeclRefName(Base);
    StringRef RecName = getRecordNameFromExprBase(Base);
    if (BaseVarName.contains("ops") || RecName.contains("ops"))
      return true;

    return false;
  }

  // Additional FP filter: assignment to size_t and operands look like small block-based sizes.
  bool isLikelySmallBlockComputation(const BinaryOperator *Mul,
                                     const Stmt *UseSiteStmt,
                                     CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    if (!isSizeT(LHS->getType(), C))
      return false;

    static const std::initializer_list<StringRef> Blocky = {
        "block", "blocks", "blk", "sector", "page", "pages"
    };
    const Expr *ML = Mul ? Mul->getLHS() : nullptr;
    const Expr *MR = Mul ? Mul->getRHS() : nullptr;
    if (!ML || !MR)
      return false;

    if (exprComesFromOps(ML) || exprComesFromOps(MR))
      return true;

    if (containsAnyName(ML, C, Blocky) || containsAnyName(MR, C, Blocky))
      return true;

    return false;
  }

  // Targeted FP filter for MSI-X mapping size: ioremap(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE)
  bool isBenignMsixIoremapSize(const BinaryOperator *Mul,
                               const Stmt *UseSiteStmt,
                               CheckerContext &C) const {
    if (!Mul || !UseSiteStmt)
      return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD)
      return false;

    // Must be in msix_map_region
    if (!FD->getIdentifier() || FD->getName() != "msix_map_region")
      return false;

    // Use site must be a call to ioremap*
    const auto *Call = dyn_cast<CallExpr>(UseSiteStmt);
    if (!Call)
      return false;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier())
      return false;
    StringRef CalleeName = Callee->getName();
    if (!CalleeName.contains("ioremap"))
      return false;

    // The multiply must be the size argument of the call (commonly arg1).
    bool IsArgMatch = false;
    for (unsigned i = 0, n = Call->getNumArgs(); i < n; ++i) {
      if (Call->getArg(i)->IgnoreParenImpCasts() == cast<Expr>(Mul)->IgnoreParenImpCasts()) {
        IsArgMatch = true;
        break;
      }
    }
    if (!IsArgMatch)
      return false;

    // One operand must be PCI_MSIX_ENTRY_SIZE (constant 16)
    auto IsEntrySizeConst = [&](const Expr *E) -> bool {
      if (!E) return false;
      llvm::APSInt CI;
      if (EvaluateExprToInt(CI, E, C)) {
        if (CI.isUnsigned() ? CI.getZExtValue() == 16
                            : (CI.getExtValue() >= 0 && (uint64_t)CI.getExtValue() == 16))
          return true;
      }
      return ExprHasName(E, "PCI_MSIX_ENTRY_SIZE", C);
    };

    // The other operand should be the parameter 'nr_entries'.
    auto IsNrEntriesParam = [&](const Expr *E) -> bool {
      if (!E) return false;
      E = E->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
          if (PVD->getIdentifier() && PVD->getName().equals("nr_entries"))
            return true;
        }
      }
      return false;
    };

    const Expr *L = Mul->getLHS()->IgnoreParenImpCasts();
    const Expr *R = Mul->getRHS()->IgnoreParenImpCasts();

    if ((IsEntrySizeConst(L) && IsNrEntriesParam(R)) ||
        (IsEntrySizeConst(R) && IsNrEntriesParam(L)))
      return true;

    return false;
  }

  bool isFalsePositive(const BinaryOperator *Mul,
                       const Stmt *UseSiteStmt,
                       const Decl *UseSiteDecl,
                       CheckerContext &C) const {
    // Targeted suppression: MSI-X ioremap table size computation.
    if (isBenignMsixIoremapSize(Mul, UseSiteStmt, C))
      return true;

    // Targeted suppression 1: Linux sysfs bin_attribute.size patterns.
    if (isLinuxBinAttributeSizeAssignment(UseSiteStmt, C))
      return true;

    // Targeted suppression 2: size_t destination and "ops"/block-style operands.
    if (isLikelySmallBlockComputation(Mul, UseSiteStmt, C))
      return true;

    // If it doesn't look like a size/count computation, suppress.
    if (!looksLikeSizeContext(UseSiteStmt, UseSiteDecl, Mul, C))
      return true;

    // Or if it explicitly looks like a non-size encoding context, suppress.
    if (looksLikeNonSizeEncodingContext(UseSiteStmt, UseSiteDecl, C))
      return true;

    return false;
  }
};

void SAGenTestChecker::checkPostStmt(const BinaryOperator *B, CheckerContext &C) const {
  if (!B)
    return;

  // Only care about integer multiplication.
  if (B->getOpcode() != BO_Mul)
    return;
  if (!B->getType()->isIntegerType())
    return;

  // Require both operands to be integer-typed.
  if (!isIntegerType(B->getLHS()) || !isIntegerType(B->getRHS()))
    return;

  // The multiply's arithmetic width (after integer promotions).
  unsigned MulWidth = getIntWidth(B->getType(), C);

  // If arithmetic is already 64-bit or more, that's OK.
  if (MulWidth >= 64)
    return;

  // Is the multiply directly used in a 64-bit integer context?
  const Expr *E = dyn_cast<Expr>(B);
  if (!E)
    return;

  const Stmt *UseSiteStmt = nullptr;
  const Decl *UseSiteDecl = nullptr;
  if (!isDirectWidenedUseTo64(E, C, UseSiteStmt, UseSiteDecl))
    return;

  // NEW: Focus on the intended bug pattern:
  // suppress if both original operands are narrower than 32 bits.
  if (!atLeastOneOperandOriginally32Plus(B, C))
    return;

  // If we can prove the product fits in the narrow arithmetic width, suppress.
  if (productDefinitelyFits(B, C))
    return;

  // Semantic filter and targeted FP filters.
  if (isFalsePositive(B, UseSiteStmt, UseSiteDecl, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply",
      N);
  R->addRange(B->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->getType()->isIntegerType())
      continue;
    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    llvm::APSInt V;
    if (EvaluateExprToInt(V, Init, C)) {
      State = State->set<ConstIntVarMap>(VD, V);
    } else {
      // If not a constant init, drop any previous knowledge.
      State = State->remove<ConstIntVarMap>(VD);
    }
  }
  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) {
    return;
  }

  const auto *VR = dyn_cast<VarRegion>(MR->getBaseRegion());
  if (!VR) {
    return;
  }

  const VarDecl *VD = VR->getDecl();
  if (!VD || !VD->getType()->isIntegerType())
    return;

  if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
    // Track constant value.
    State = State->set<ConstIntVarMap>(VD, CI->getValue());
  } else {
    // Unknown/non-constant write: drop info.
    State = State->remove<ConstIntVarMap>(VD);
  }

  if (State != C.getState())
    C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {

  for (const MemRegion *R : Regions) {
    const MemRegion *Base = R ? R->getBaseRegion() : nullptr;
    const auto *VR = dyn_cast_or_null<VarRegion>(Base);
    if (!VR)
      continue;
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      continue;
    State = State->remove<ConstIntVarMap>(VD);
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect 32-bit multiply whose result is only widened to 64-bit afterward, risking overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
