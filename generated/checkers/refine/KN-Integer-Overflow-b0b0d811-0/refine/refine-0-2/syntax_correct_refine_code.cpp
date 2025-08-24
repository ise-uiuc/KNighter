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
bool functionKnownToDeref(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &DerefParams);
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

  // Finds a suspicious '*' on the value-producing path of Root.
  static bool findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                unsigned TargetBits,
                                                const BinaryOperator *&OutMul,
                                                CheckerContext &C);

  // Extract a variable/field identifier name from an expression if possible.
  static std::string extractIdentifierLikeName(const Expr *E);

  static bool nameContains(StringRef TextLower,
                           std::initializer_list<StringRef> Needles);

  static std::string toLowerCopy(StringRef S);

  // Additional helper: obtain current function name if available.
  static std::string getCurrentFunctionName(CheckerContext &C);

  // Additional helper: check if a type is (typedef) named as the given Name
  // along the typedef chain.
  static bool isTypedefNamedInChain(QualType QT, StringRef Name);

  // Risky LHS names we never suppress for.
  static bool isRiskyWideAccumulatorLHS(const Expr *LHS);

  // Heuristic: index-like vs stride-like names for ALSA PCM offset computations.
  static bool isIndexLikeName(StringRef LowerName);
  static bool isStrideLikeName(StringRef LowerName);

  // Extract something name-like from an operand to examine.
  static std::string extractOperandName(const Expr *Op);

  // Known benign contexts (time arithmetic).
  static bool isFalsePositiveContext_Time(const Expr *Root,
                                          const BinaryOperator *MulBO,
                                          CheckerContext &C);

  // Heuristic FP filter for index * stride patterns used in PCM pointer getters.
  static bool isFalsePositiveContext_IndexTimesStride(const Expr *Root,
                                                      const BinaryOperator *MulBO,
                                                      const Expr *LHS,
                                                      CheckerContext &C);

  // Unified FP predicate invoking specific filters.
  static bool isFalsePositive(const Expr *Root,
                              const BinaryOperator *MulBO,
                              const Expr *LHS,
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

// Restrict traversal to the value-producing path of Root:
// - Do NOT traverse into CallExpr arguments: their values do not form the
//   final rvalue assigned; the call's return value does.
// - Do NOT traverse into expressions that only compute addresses/indices
//   (ArraySubscriptExpr index, MemberExpr base, UnaryOperator UO_Deref/UO_AddrOf).
// - Traverse through arithmetic, casts, parentheses, comma (RHS only), and
//   conditional operator arms.
// Return true and set OutMul if a '*' is found whose result type is narrower
// than TargetBits and is on the value path.
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
          OutMul = BO;
          return true;
        }
      }
      // Even if not suspicious, do not stop searching; sub-operands might contain another mul.
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

std::string SAGenTestChecker::toLowerCopy(StringRef S) {
  std::string Out = S.str();
  std::transform(Out.begin(), Out.end(), Out.begin(), ::tolower);
  return Out;
}

std::string SAGenTestChecker::getCurrentFunctionName(CheckerContext &C) {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return {};
  const Decl *D = LC->getDecl();
  if (!D)
    return {};
  if (const auto *FD = dyn_cast<FunctionDecl>(D))
    return FD->getNameAsString();
  return {};
}

bool SAGenTestChecker::isTypedefNamedInChain(QualType QT, StringRef Name) {
  // Walk through typedef sugar chain to see if any typedef matches Name.
  QualType Cur = QT;
  // Limit the iteration to avoid pathological cases.
  for (int i = 0; i < 8; ++i) {
    if (const auto *TDT = dyn_cast<TypedefType>(Cur.getTypePtrOrNull())) {
      if (TDT->getDecl() && TDT->getDecl()->getName() == Name)
        return true;
      Cur = TDT->getDecl()->getUnderlyingType();
      continue;
    }
    break;
  }
  return false;
}

bool SAGenTestChecker::isRiskyWideAccumulatorLHS(const Expr *LHS) {
  if (!LHS)
    return false;
  std::string N = extractIdentifierLikeName(LHS);
  std::string NL = toLowerCopy(N);
  // Fields/variables like size, addr, dma_addr, iova, len, length, bytes, count are risky accumulators.
  if (nameContains(NL, {"size", "addr", "dma_addr", "iova", "offset", "ofs",
                        "length", "len", "bytes", "nbytes", "count", "total"}))
    return true;

  // Also treat dma_addr_t explicitly as risky by typedef name on LHS type.
  QualType LT = LHS->getType();
  if (isTypedefNamedInChain(LT, "dma_addr_t"))
    return true;

  return false;
}

bool SAGenTestChecker::isIndexLikeName(StringRef LowerName) {
  return nameContains(LowerName, {"idx", "index", "ind", "buffer", "buf",
                                  "currentbuffer", "ring", "page"});
}

bool SAGenTestChecker::isStrideLikeName(StringRef LowerName) {
  return nameContains(LowerName, {"frame", "frames", "stride", "period",
                                  "chunk", "pitch", "bpp", "cpp"});
}

std::string SAGenTestChecker::extractOperandName(const Expr *Op) {
  if (!Op)
    return {};
  // Try to get an identifier/field name.
  std::string N = extractIdentifierLikeName(Op);
  if (!N.empty())
    return N;

  // Fall back to a short source snippet when no identifier is present.
  // Only use it for name probing via substrings.
  return {};
}

// Secondary guard: filter known jiffies/timeout contexts to avoid false positives.
bool SAGenTestChecker::isFalsePositiveContext_Time(const Expr *Root,
                                                   const BinaryOperator *MulBO,
                                                   CheckerContext &C) {
  (void)MulBO;

  // 1) If the RHS/root expression text contains "jiffies", we treat this as
  //    time arithmetic; suppress the report.
  if (ExprHasName(Root, "jiffies", C))
    return true;

  // 2) If the parent assignment/compound-assignment LHS name implies timeout-like field,
  //    suppress as well.
  //    Common patterns: expires, expiry, timeout, deadline, jiffies.
  const CompoundAssignOperator *CAO =
      findSpecificTypeInParents<CompoundAssignOperator>(Root, C);
  const BinaryOperator *AssignBO =
      findSpecificTypeInParents<BinaryOperator>(Root, C);

  const Expr *LHSExpr = nullptr;
  if (CAO) {
    LHSExpr = CAO->getLHS();
  } else if (AssignBO && AssignBO->getOpcode() == BO_Assign) {
    LHSExpr = AssignBO->getLHS();
  }

  if (LHSExpr) {
    std::string LHSName = extractIdentifierLikeName(LHSExpr);
    if (!LHSName.empty()) {
      std::string Lower = toLowerCopy(LHSName);
      if (nameContains(Lower, {"expire", "expiry", "timeout", "deadline", "jiffies"}))
        return true;
    }
  }

  return false;
}

// Heuristic FP filter for ALSA-like index*stride multiplication used inside
// PCM pointer getters that return a frame position.
// Conditions (any strong subset is enough):
//  - Function name contains "pointer" AND
//  - LHS type is snd_pcm_uframes_t OR LHS name is "pos"
//  - RHS mul has one index-like operand and one stride-like operand
// Do NOT suppress if the LHS looks like a risky wide accumulator (size/addr/len/etc.).
bool SAGenTestChecker::isFalsePositiveContext_IndexTimesStride(const Expr *Root,
                                                               const BinaryOperator *MulBO,
                                                               const Expr *LHS,
                                                               CheckerContext &C) {
  if (!MulBO)
    return false;

  if (!LHS)
    return false;

  // Never suppress risky accumulators.
  if (isRiskyWideAccumulatorLHS(LHS))
    return false;

  // Check function name context.
  std::string FnName = getCurrentFunctionName(C);
  std::string FnLower = toLowerCopy(FnName);
  bool InPointerGetter = !FnLower.empty() && FnLower.find("pointer") != std::string::npos;

  // LHS type/name hints (common in ALSA).
  QualType LT = LHS->getType();
  bool IsUFrames = isTypedefNamedInChain(LT, "snd_pcm_uframes_t");
  std::string LHSName = extractIdentifierLikeName(LHS);
  std::string LHSNameLower = toLowerCopy(LHSName);
  bool IsPosLHS = nameContains(LHSNameLower, {"pos", "position"});

  // Require at least some function/LHS context.
  if (!(InPointerGetter || IsUFrames || IsPosLHS))
    return false;

  // Names of operands.
  const Expr *L = MulBO->getLHS();
  const Expr *R = MulBO->getRHS();
  std::string LName = extractOperandName(L);
  std::string RName = extractOperandName(R);
  std::string LLower = toLowerCopy(LName);
  std::string RLower = toLowerCopy(RName);

  bool IndexStridePattern =
      (isIndexLikeName(LLower) && isStrideLikeName(RLower)) ||
      (isIndexLikeName(RLower) && isStrideLikeName(LLower));

  if (!IndexStridePattern) {
    // As a fallback, scan the expression text for "buffer" and "frame".
    bool HasBuffer = ExprHasName(Root, "buffer", C);
    bool HasFrame = ExprHasName(Root, "frame", C) || ExprHasName(Root, "frames", C);
    IndexStridePattern = HasBuffer && HasFrame;
  }

  if (!IndexStridePattern)
    return false;

  // If we reached here, it's very likely a benign frames position computation.
  return true;
}

bool SAGenTestChecker::isFalsePositive(const Expr *Root,
                                       const BinaryOperator *MulBO,
                                       const Expr *LHS,
                                       CheckerContext &C) {
  // Time arithmetic/jiffies is benign.
  if (isFalsePositiveContext_Time(Root, MulBO, C))
    return true;

  // ALSA PCM pointer index*stride pattern.
  if (isFalsePositiveContext_IndexTimesStride(Root, MulBO, LHS, C))
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

  SmallString<128> Msg;
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
      // Build a fake LHS Expr interface via a DeclRefExpr-like context is not necessary,
      // but we can still pass nullptr or special-case the name via VD.
      // Construct a minimal LHS proxy: reuse VD->getInit() parent search for assignment name.
      // For name filtering we can use VD directly.
      // Here, create a small shim Expr pointer: we will not rely on it; pass nullptr and
      // rely on time/jiffies-only filter.
      const Expr *LHSExpr = nullptr;
      // However, we still want the risk-name filter; emulate via a small check:
      // If variable name is risky, we don't suppress benign contexts.
      bool RiskyName = false;
      {
        std::string VN = VD->getNameAsString();
        std::string VNL = toLowerCopy(VN);
        if (nameContains(VNL, {"size", "addr", "dma_addr", "iova", "offset", "ofs",
                               "length", "len", "bytes", "nbytes", "count", "total"}))
          RiskyName = true;
      }

      bool Suppress = !RiskyName && isFalsePositive(Init, MulBO, LHSExpr, C);
      if (MulBO && !isConstantFolded(MulBO, C) && !Suppress) {
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
