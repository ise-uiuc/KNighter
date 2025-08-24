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
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallString.h"
#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided in the prompt.
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

namespace {

class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::PostStmt<DeclStmt>> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
                                     "Mixed-width multiplication may overflow before widening",
                                     "Integer")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;

private:
  // Helpers
  static unsigned getTypeBitWidth(QualType QT, CheckerContext &C);
  static bool isIntegerLike(QualType QT);
  static bool isWideTargetType(QualType QT, CheckerContext &C);
  static bool isConstantFolded(const Expr *E, CheckerContext &C);

  // Range reasoning helpers to suppress FPs when product fits in the mul's type.
  static bool getMaxForExpr(const Expr *E, CheckerContext &C,
                            llvm::APSInt &Max, bool &IsNonNegative, bool &Known);
  static llvm::APSInt getMaxForType(QualType QT, CheckerContext &C);
  static bool productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                          QualType MulType, CheckerContext &C);

  // Finds a suspicious '*' on the value-producing path of Root.
  static bool findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                unsigned TargetBits,
                                                const BinaryOperator *&OutMul,
                                                CheckerContext &C);

  // Extract a variable/field identifier name from an expression if possible.
  static std::string extractIdentifierLikeName(const Expr *E);

  static bool nameContains(StringRef TextLower,
                           std::initializer_list<StringRef> Needles);

  // Address/size-like LHS filter for intended bug surface (narrowed).
  static bool isAddressOrSizeLikeLHS(const Expr *LHS);

  // IRQ-like and jiffies contexts suppression.
  static bool isIrqLikeContext(const Expr *Root, const Expr *LHS, CheckerContext &C);

  // Kernel block/folio I/O math suppression helpers
  static bool isShiftOfOne(const Expr *E);
  static bool exprNameContains(const Expr *E, std::initializer_list<StringRef> Needles,
                               CheckerContext &C);
  static bool isBlockSizeLikeExpr(const Expr *E, CheckerContext &C);
  static bool isAddSubChainRec(const Expr *E,
                               std::initializer_list<StringRef> Needles,
                               CheckerContext &C);
  static bool isAddSubChainOfNames(const Expr *E,
                                   std::initializer_list<StringRef> Needles,
                                   CheckerContext &C);
  static bool isBlockCountLikeExpr(const Expr *E, CheckerContext &C);
  static bool isPageOrFolioContext(const Expr *Root, CheckerContext &C);

  // Heuristic: detect known-timeout/jiffies/IRQ contexts to avoid FPs.
  static bool isFalsePositiveContext(const Expr *Root,
                                     const BinaryOperator *MulBO,
                                     const Expr *LHSExpr,
                                     CheckerContext &C);

  // FP suppressors for cases where '*' is not contributing directly to the value
  // assigned/added to the wide type.
  static bool isMulUnderCallArg(const BinaryOperator *MulBO,
                                const Expr *Root,
                                CheckerContext &C);
  static bool isMulUnderArrayIndex(const BinaryOperator *MulBO,
                                   CheckerContext &C);

  // Aggregated FP gate.
  static bool isFalsePositive(const Expr *Root,
                              const BinaryOperator *MulBO,
                              const Expr *LHSExpr,
                              CheckerContext &C);

  void emitReport(const BinaryOperator *MulBO, QualType LHSType,
                  CheckerContext &C) const;
};

// Return bit width of a type.
unsigned SAGenTestChecker::getTypeBitWidth(QualType QT, CheckerContext &C) {
  return C.getASTContext().getTypeSize(QT);
}

// Check for integer-like types (integers and enums), ignoring typedefs/quals.
bool SAGenTestChecker::isIntegerLike(QualType QT) {
  QT = QT.getCanonicalType();
  return QT->isIntegerType() || QT->isEnumeralType();
}

// Wide target: integer-like and width >= 64 bits (covers u64, dma_addr_t on 64-bit).
bool SAGenTestChecker::isWideTargetType(QualType QT, CheckerContext &C) {
  if (!isIntegerLike(QT))
    return false;

  unsigned Bits = getTypeBitWidth(QT, C);
  return Bits >= 64;
}

// Try to fold expression to constant integer. If succeeds, skip reporting.
bool SAGenTestChecker::isConstantFolded(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt EvalRes;
  return EvaluateExprToInt(EvalRes, E, C);
}

// Compute max value representable by a type (signed or unsigned).
llvm::APSInt SAGenTestChecker::getMaxForType(QualType QT, CheckerContext &C) {
  unsigned Bits = getTypeBitWidth(QT, C);
  bool IsUnsigned = QT->isUnsignedIntegerType();
  llvm::APInt MaxAP = IsUnsigned ? llvm::APInt::getMaxValue(Bits)
                                 : llvm::APInt::getSignedMaxValue(Bits);
  return llvm::APSInt(MaxAP, IsUnsigned);
}

// Obtain a conservative maximum for an expression and whether it is non-negative.
// Known is true if we could establish a bound; false if unknown.
bool SAGenTestChecker::getMaxForExpr(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Max, bool &IsNonNegative, bool &Known) {
  if (!E) {
    Known = false;
    IsNonNegative = false;
    return false;
  }

  E = E->IgnoreParenImpCasts();

  // 1) Integer literal or compile-time constant.
  if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
    Max = llvm::APSInt(IL->getValue(), /*IsUnsigned=*/false);
    IsNonNegative = !Max.isSigned() || Max.isNonNegative();
    Known = true;
    return true;
  }

  // Attempt constant-fold.
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, E, C)) {
    Max = EvalRes;
    IsNonNegative = !Max.isSigned() || Max.isNonNegative();
    Known = true;
    return true;
  }

  // 2) Concrete SVal from the engine.
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(E, C.getLocationContext());

  if (auto CI = SV.getAs<nonloc::ConcreteInt>()) {
    Max = CI->getValue();
    IsNonNegative = !Max.isSigned() || Max.isNonNegative();
    Known = true;
    return true;
  }

  // 3) Symbolic upper bound from constraints.
  if (SymbolRef Sym = SV.getAsSymbol()) {
    if (const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C)) {
      Max = *MaxVal;
      IsNonNegative = !Max.isSigned() || Max.isNonNegative();
      Known = true;
      return true;
    }
  }

  // 4) Fallback: type-based bound.
  QualType QT = E->getType();
  if (isIntegerLike(QT)) {
    Max = getMaxForType(QT, C);
    // For unsigned integer types, we know it's non-negative.
    IsNonNegative = QT->isUnsignedIntegerType();
    Known = true;
    return true;
  }

  Known = false;
  IsNonNegative = false;
  return false;
}

// If both operands are known non-negative and we can bound their maxima,
// check if the product of these maxima definitely fits in MulType.
// Return true only if we can prove it fits (hence no overflow possible).
bool SAGenTestChecker::productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                                   QualType MulType, CheckerContext &C) {
  llvm::APSInt MaxL, MaxR;
  bool NN_L = false, NN_R = false, KnownL = false, KnownR = false;

  getMaxForExpr(L, C, MaxL, NN_L, KnownL);
  getMaxForExpr(R, C, MaxR, NN_R, KnownR);

  if (!(KnownL && KnownR && NN_L && NN_R))
    return false; // Cannot prove safety.

  // Compute product in a sufficiently wide unsigned APInt domain.
  const unsigned WideBits = 128;
  llvm::APInt LExt = MaxL.isSigned() ? MaxL.sext(WideBits) : MaxL.zext(WideBits);
  llvm::APInt RExt = MaxR.isSigned() ? MaxR.sext(WideBits) : MaxR.zext(WideBits);
  llvm::APInt Prod = LExt * RExt;

  // Compare against maximum representable in the mul's (promoted) result type.
  unsigned MulBits = getTypeBitWidth(MulType, C);
  bool MulUnsigned = MulType->isUnsignedIntegerType();
  llvm::APInt MulMax = MulUnsigned ? llvm::APInt::getMaxValue(MulBits)
                                   : llvm::APInt::getSignedMaxValue(MulBits);
  llvm::APInt MulMaxExt = MulMax.zextOrTrunc(WideBits);

  // Since product is non-negative, unsigned compare suffices.
  if (Prod.ule(MulMaxExt))
    return true; // Definitely fits -> no overflow in narrower mul type.

  return false;
}

// Restrict traversal to the value-producing path of Root.
bool SAGenTestChecker::findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                         unsigned TargetBits,
                                                         const BinaryOperator *&OutMul,
                                                         CheckerContext &C) {
  if (!Root)
    return false;

  const Expr *E = Root->IgnoreParenImpCasts();

  // Handle binary operators explicitly.
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperatorKind Op = BO->getOpcode();

    if (Op == BO_Mul) {
      QualType ResT = BO->getType();
      if (isIntegerLike(ResT)) {
        unsigned MulBits = getTypeBitWidth(ResT, C);
        if (MulBits < TargetBits) {
          // New guard: if we can prove the product cannot overflow in ResT,
          // then it is safe and should not be considered suspicious.
          if (!productDefinitelyFitsInType(BO->getLHS(), BO->getRHS(), ResT, C)) {
            OutMul = BO;
            return true;
          }
        }
      }
      // Even if not suspicious, continue searching sub-expressions.
      if (findFirstSuspiciousMulOnValuePath(BO->getLHS(), TargetBits, OutMul, C))
        return true;
      if (findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C))
        return true;
      return false;
    }

    // For comma operator, only the RHS contributes to the resulting value.
    if (Op == BO_Comma) {
      return findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C);
    }

    // For simple assignment in a subexpression, only RHS determines resulting value.
    if (Op == BO_Assign) {
      return findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C);
    }

    // For other arithmetic/bitwise operators, both sides contribute to value.
    if (findFirstSuspiciousMulOnValuePath(BO->getLHS(), TargetBits, OutMul, C))
      return true;
    if (findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C))
      return true;
    return false;
  }

  // Conditional operator: either arm may be the resulting value.
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    if (findFirstSuspiciousMulOnValuePath(CO->getTrueExpr(), TargetBits, OutMul, C))
      return true;
    if (findFirstSuspiciousMulOnValuePath(CO->getFalseExpr(), TargetBits, OutMul, C))
      return true;
    return false;
  }

  // Unary operator: break on address/indirection which form lvalue/address computation.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    UnaryOperatorKind UOK = UO->getOpcode();
    if (UOK == UO_AddrOf || UOK == UO_Deref)
      return false;
    return findFirstSuspiciousMulOnValuePath(UO->getSubExpr(), TargetBits, OutMul, C);
  }

  // Explicit casts: continue through.
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    return findFirstSuspiciousMulOnValuePath(CE->getSubExpr(), TargetBits, OutMul, C);
  }

  // Do not traverse into call arguments: call's return value is the value path.
  if (isa<CallExpr>(E))
    return false;

  // Array subscripts: indexing/math does not become the resulting rvalue itself.
  if (isa<ArraySubscriptExpr>(E))
    return false;

  // Member access: base computation does not propagate to the value itself.
  if (isa<MemberExpr>(E))
    return false;

  // Default: stop if leaf or non-handled node on value path.
  return false;
}

// Extract identifier-like name from an expression (variable or field), else empty.
std::string SAGenTestChecker::extractIdentifierLikeName(const Expr *E) {
  if (!E)
    return {};
  E = E->IgnoreParenImpCasts();

  // Look through deref to get the underlying identifier.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref || UO->getOpcode() == UO_AddrOf)
      return extractIdentifierLikeName(UO->getSubExpr());
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
      return FD->getNameAsString();
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
      return ND->getNameAsString();
  }
  return {};
}

bool SAGenTestChecker::nameContains(StringRef TextLower,
                                    std::initializer_list<StringRef> Needles) {
  for (StringRef N : Needles) {
    if (TextLower.contains(N))
      return true;
  }
  return false;
}

// Address/size-like LHS filter for intended bug surface (narrowed).
// Focus on addr/size/pitch/stride-like sinks. Avoid generic "len", "offset" to reduce FPs.
bool SAGenTestChecker::isAddressOrSizeLikeLHS(const Expr *LHS) {
  std::string Name = extractIdentifierLikeName(LHS);
  if (Name.empty())
    return false;
  std::string Lower = Name;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);

  // Heuristic keywords that map to memory/byte/size/address semantics.
  return nameContains(Lower,
                      {"addr", "address", "dma_addr",
                       "size", "bytes", "nbytes",
                       "pitch", "stride"});
}

// IRQ-like context suppression.
bool SAGenTestChecker::isIrqLikeContext(const Expr *Root, const Expr *LHS, CheckerContext &C) {
  // LHS name contains irq-ish patterns (e.g., out_hwirq).
  std::string LHSName = extractIdentifierLikeName(LHS);
  std::string Lower = LHSName;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
  if (!Lower.empty() && nameContains(Lower, {"irq", "hwirq", "intid", "gsi", "spi", "ppi"}))
    return true;

  // Function name contains irq-domain style names (e.g., *_irq_domain_*xlate*).
  const FunctionDecl *FD = nullptr;
  if (const auto *LC = C.getLocationContext())
    FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (FD) {
    std::string FName = FD->getNameAsString();
    std::transform(FName.begin(), FName.end(), FName.begin(), ::tolower);
    if (nameContains(FName, {"irq", "hwirq", "xlate", "irq_domain"}))
      return true;
  }

  // Source expression text heuristic.
  if (ExprHasName(Root, "jiffies", C) || ExprHasName(Root, "irq", C) ||
      ExprHasName(Root, "hwirq", C))
    return true;

  return false;
}

// Returns true if expression is of the form (1 << X) or (1U << X).
bool SAGenTestChecker::isShiftOfOne(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Shl)
    return false;
  const auto *LHS_IL = dyn_cast<IntegerLiteral>(BO->getLHS()->IgnoreParenImpCasts());
  if (!LHS_IL) return false;
  return LHS_IL->getValue() == 1;
}

bool SAGenTestChecker::exprNameContains(const Expr *E,
                                        std::initializer_list<StringRef> Needles,
                                        CheckerContext &C) {
  if (!E) return false;
  // Try identifier name first.
  std::string Name = extractIdentifierLikeName(E);
  std::string Lower = Name;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
  if (!Lower.empty() && nameContains(Lower, Needles))
    return true;
  // Fallback to source text.
  for (StringRef N : Needles) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

// block-size-like: variable named block_size/blksize/bsize/fs_block_size
// OR an expression like (1 << block_bits) or (1U << blkbits)
bool SAGenTestChecker::isBlockSizeLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  if (exprNameContains(E, {"block_size", "blksize", "bsize", "fs_block_size",
                           "page_size", "blocksize"}, C))
    return true;
  if (isShiftOfOne(E))
    return true;
  // Also accept (1 << something) nested within parens/casts.
  return false;
}

// recursively check if E is a +/- chain composed of names from Needles and integer literals
bool SAGenTestChecker::isAddSubChainRec(const Expr *E,
                                        std::initializer_list<StringRef> Needles,
                                        CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (isa<IntegerLiteral>(E))
    return true;
  if (exprNameContains(E, Needles, C))
    return true;
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add || BO->getOpcode() == BO_Sub) {
      return isAddSubChainRec(BO->getLHS(), Needles, C) &&
             isAddSubChainRec(BO->getRHS(), Needles, C);
    }
  }
  return false;
}

// count-like: combinations like (last - i + 1), (nr_blks), (blocks), etc.
bool SAGenTestChecker::isAddSubChainOfNames(const Expr *E,
                                            std::initializer_list<StringRef> Needles,
                                            CheckerContext &C) {
  return isAddSubChainRec(E, Needles, C);
}

bool SAGenTestChecker::isBlockCountLikeExpr(const Expr *E, CheckerContext &C) {
  // Common identifiers in block/folio counting contexts.
  return isAddSubChainOfNames(
      E,
      {"first", "last", "end", "i", "j", "k", "count", "nr", "nr_blks",
       "nr_blocks", "blocks", "blks", "nblocks", "nblks", "block"},
      C);
}

// Identify iomap/folio/page context from function name or expression text.
bool SAGenTestChecker::isPageOrFolioContext(const Expr *Root, CheckerContext &C) {
  const FunctionDecl *FD = nullptr;
  if (const auto *LC = C.getLocationContext())
    FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (FD) {
    std::string FName = FD->getNameAsString();
    std::transform(FName.begin(), FName.end(), FName.begin(), ::tolower);
    if (nameContains(FName, {"iomap", "folio", "readahead", "readpage"}))
      return true;
  }
  // Fallback to textual hints.
  if (ExprHasName(Root, "folio", C) || ExprHasName(Root, "iomap", C) ||
      ExprHasName(Root, "page", C))
    return true;
  return false;
}

// Secondary guard: filter known benign contexts to avoid false positives.
bool SAGenTestChecker::isFalsePositiveContext(const Expr *Root,
                                              const BinaryOperator *MulBO,
                                              const Expr *LHSExpr,
                                              CheckerContext &C) {
  (void)MulBO;

  // 1) Time arithmetic.
  if (ExprHasName(Root, "jiffies", C))
    return true;

  // 2) Timeout-like LHS names.
  const CompoundAssignOperator *CAO =
      findSpecificTypeInParents<CompoundAssignOperator>(Root, C);
  const BinaryOperator *AssignBO =
      findSpecificTypeInParents<BinaryOperator>(Root, C);

  const Expr *LHS = LHSExpr;
  if (!LHS) {
    if (CAO)
      LHS = CAO->getLHS();
    else if (AssignBO && AssignBO->getOpcode() == BO_Assign)
      LHS = AssignBO->getLHS();
  }

  if (LHS) {
    std::string LHSName = extractIdentifierLikeName(LHS);
    if (!LHSName.empty()) {
      std::string Lower = LHSName;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      if (nameContains(Lower, {"expire", "expiry", "timeout", "deadline", "jiffies"}))
        return true;
    }
  }

  // 3) IRQ-like contexts.
  if (LHS && isIrqLikeContext(Root, LHS, C))
    return true;

  // 4) Kernel iomap/folio math: count-like * block-size-like, in page/folio context.
  if (MulBO && isPageOrFolioContext(Root, C)) {
    const Expr *ML = MulBO->getLHS()->IgnoreParenImpCasts();
    const Expr *MR = MulBO->getRHS()->IgnoreParenImpCasts();
    bool IsBlockGeom =
        (isBlockSizeLikeExpr(ML, C) && isBlockCountLikeExpr(MR, C)) ||
        (isBlockSizeLikeExpr(MR, C) && isBlockCountLikeExpr(ML, C));
    if (IsBlockGeom)
      return true;
  }

  return false;
}

// Return true if the '*' is nested under a CallExpr (i.e., used as a call argument)
// relative to the current assignment/addition root.
bool SAGenTestChecker::isMulUnderCallArg(const BinaryOperator *MulBO,
                                         const Expr *Root,
                                         CheckerContext &C) {
  (void)Root;
  const CallExpr *CE = findSpecificTypeInParents<CallExpr>(MulBO, C);
  return CE != nullptr;
}

// Return true if '*' is used solely as part of an ArraySubscriptExpr (index).
bool SAGenTestChecker::isMulUnderArrayIndex(const BinaryOperator *MulBO,
                                            CheckerContext &C) {
  const ArraySubscriptExpr *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(MulBO, C);
  return ASE != nullptr;
}

// Aggregated FP logic.
bool SAGenTestChecker::isFalsePositive(const Expr *Root,
                                       const BinaryOperator *MulBO,
                                       const Expr *LHSExpr,
                                       CheckerContext &C) {
  if (!MulBO)
    return true;

  // Suppress when LHS is not address/size-like (we target addr/size/pitch/stride).
  if (!isAddressOrSizeLikeLHS(LHSExpr))
    return true;

  // Suppress known benign contexts.
  if (isFalsePositiveContext(Root, MulBO, LHSExpr, C))
    return true;

  // Suppress when '*' is under a call arg or an array index.
  if (isMulUnderCallArg(MulBO, Root, C))
    return true;
  if (isMulUnderArrayIndex(MulBO, C))
    return true;

  return false;
}

void SAGenTestChecker::emitReport(const BinaryOperator *MulBO, QualType LHSType,
                                  CheckerContext &C) const {
  if (!MulBO)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  llvm::SmallString<128> Msg;
  Msg += "Multiplication occurs in a narrower type and is widened after; ";
  Msg += "possible overflow before assignment/addition to wide type";
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(MulBO->getSourceRange());
  C.emitReport(std::move(R));
}

// Handle assignments and compound assignments that bind values to wide targets.
void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Prefer detecting compound assignments first (e.g., +=)
  if (const auto *CAO = findSpecificTypeInParents<CompoundAssignOperator>(S, C)) {
    BinaryOperatorKind Op = CAO->getOpcode();
    // We care about adding/subtracting a product into a wide accumulator.
    if (Op == BO_AddAssign || Op == BO_SubAssign) {
      const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
      if (!LHS)
        return;
      QualType LT = LHS->getType();
      if (!isWideTargetType(LT, C))
        return;

      const BinaryOperator *MulBO = nullptr;
      const Expr *RHS = CAO->getRHS();
      if (findFirstSuspiciousMulOnValuePath(RHS, getTypeBitWidth(LT, C), MulBO, C)) {
        // Extra safety: if multiplication definitely fits in its own type, skip.
        if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                                 MulBO->getType(), C)) {
          return;
        }
        if (MulBO && !isConstantFolded(MulBO, C) &&
            !isFalsePositive(RHS, MulBO, LHS, C)) {
          emitReport(MulBO, LT, C);
        }
      }
    }
    return;
  }

  // Handle simple assignments: T_wide lhs = <expr with mul>;
  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(S, C)) {
    if (BO->getOpcode() != BO_Assign)
      return;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    if (!LHS)
      return;
    QualType LT = LHS->getType();
    if (!isWideTargetType(LT, C))
      return;

    const Expr *RHS = BO->getRHS();
    const BinaryOperator *MulBO = nullptr;
    if (findFirstSuspiciousMulOnValuePath(RHS, getTypeBitWidth(LT, C), MulBO, C)) {
      if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                               MulBO->getType(), C)) {
        return;
      }
      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositive(RHS, MulBO, LHS, C)) {
        emitReport(MulBO, LT, C);
      }
    }
  }
}

// Handle variable initializations: wide_var = <expr with mul>;
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->hasInit())
      continue;

    QualType T = VD->getType();
    if (!isWideTargetType(T, C))
      continue;

    const Expr *Init = VD->getInit();
    const BinaryOperator *MulBO = nullptr;
    if (findFirstSuspiciousMulOnValuePath(Init, getTypeBitWidth(T, C), MulBO, C)) {
      // For initialization, ensure the variable name is address/size-like.
      std::string Name = VD->getNameAsString();
      std::string Lower = Name;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      bool IsAddrSizeLike =
          nameContains(Lower,
                       {"addr", "address", "dma_addr",
                        "size", "bytes", "nbytes",
                        "pitch", "stride"});
      if (!IsAddrSizeLike)
        continue;

      if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                               MulBO->getType(), C)) {
        continue;
      }

      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositive(Init, MulBO, nullptr, C)) {
        emitReport(MulBO, T, C);
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow or mixed-width multiplication that may overflow before being assigned/added to a wide integer",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
