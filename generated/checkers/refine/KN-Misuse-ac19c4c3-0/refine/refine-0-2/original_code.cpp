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
#include "clang/AST/Stmt.h"
#include <cstdint>

using namespace clang;
using namespace ento;
using namespace taint;

// Register a map in the ProgramState to track upper bounds for symbols.
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolUpperBoundMap, SymbolRef, llvm::APSInt)

namespace {

// Track per-symbol upper bounds discovered along the path (e.g., from if (n <= K)).
class SAGenTestChecker
    : public Checker<check::PreCall, eval::Assume> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Open-coded size multiplication may overflow",
                       "Integer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                             bool Assumption) const;

private:
  // Return true if this is a target function, and set SizeIdx to the size arg.
  bool isTargetFunction(const CallEvent &Call, CheckerContext &C,
                        unsigned &SizeIdx) const;

  // Return true if E is a sizeof(...) expression.
  static bool isSizeofExpr(const Expr *E);

  // Try to evaluate expression to an integer constant.
  static bool tryEvaluateToAPSInt(const Expr *E, CheckerContext &C,
                                  llvm::APSInt &Out);

  // Extract the sizeof value (in bytes) from a sizeof expression.
  static bool getSizeofValueInBytes(const Expr *SizeofE, CheckerContext &C,
                                    uint64_t &OutBytes);

  // Compute size_t bit width.
  static unsigned getSizeTBits(CheckerContext &C);

  // Canonicalize a symbol by stripping casts.
  static SymbolRef stripCasts(SymbolRef S) {
    while (auto SC = dyn_cast_or_null<SymbolCast>(S))
      S = SC->getOperand();
    return S;
  }

  // Look for an upper bound on CountExpr using:
  // - compile-time constant,
  // - path constraints via ConstraintManager,
  // - our own SymbolUpperBoundMap,
  // - or integral type-width fallback (not constraint-derived).
  // Returns true if any bound was found. Sets HasConstraintBound true
  // only if the bound came from constraints or our map (not just type max).
  static bool getUpperBoundForCount(const Expr *CountExpr, CheckerContext &C,
                                    llvm::APInt &MaxCount, bool &HasConstraintBound,
                                    bool &IsTainted);

  // Returns true if multiplication elemSize * Count cannot overflow size_t.
  static bool productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                       const llvm::APInt &MaxCount,
                                       CheckerContext &C);

  // Helper to suppress reports in provably safe situations.
  static bool isFalsePositive(const Expr *CountExpr, uint64_t ElemSizeBytes,
                              CheckerContext &C, bool &IsTainted, bool &HasConstraintBound);

  // Report a concise diagnostic on SizeE.
  void report(const Expr *SizeE, CheckerContext &C) const;

  // Attempt to record an upper bound from a relational symbolic expression
  // under the given branch assumption.
  ProgramStateRef recordUpperBoundFromBinarySymExpr(ProgramStateRef State,
                                                    const BinarySymExpr *BSE,
                                                    bool Assumption,
                                                    const ASTContext &AC) const;
};

bool SAGenTestChecker::isTargetFunction(const CallEvent &Call,
                                        CheckerContext &C,
                                        unsigned &SizeIdx) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Match Linux copy_to/from_user calls by spelled name.
  if (ExprHasName(OE, "copy_from_user", C) || ExprHasName(OE, "copy_to_user", C)) {
    if (Call.getNumArgs() > 2) {
      SizeIdx = 2; // (dst, src, size)
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!E)
    return false;
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    return U->getKind() == UETT_SizeOf;
  }
  return false;
}

bool SAGenTestChecker::tryEvaluateToAPSInt(const Expr *E, CheckerContext &C,
                                           llvm::APSInt &Out) {
  if (!E)
    return false;
  return EvaluateExprToInt(Out, E->IgnoreParenImpCasts(), C);
}

bool SAGenTestChecker::getSizeofValueInBytes(const Expr *SizeofE, CheckerContext &C,
                                             uint64_t &OutBytes) {
  llvm::APSInt V;
  if (!tryEvaluateToAPSInt(SizeofE, C, V))
    return false;
  OutBytes = V.getLimitedValue(/*Max*/UINT64_MAX);
  return true;
}

unsigned SAGenTestChecker::getSizeTBits(CheckerContext &C) {
  ASTContext &ACtx = C.getASTContext();
  return ACtx.getTypeSize(ACtx.getSizeType()); // in bits
}

bool SAGenTestChecker::getUpperBoundForCount(const Expr *CountExpr, CheckerContext &C,
                                             llvm::APInt &MaxCount,
                                             bool &HasConstraintBound,
                                             bool &IsTainted) {
  HasConstraintBound = false;
  IsTainted = false;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // If CountExpr is a compile-time constant, use that.
  llvm::APSInt ConstVal;
  if (tryEvaluateToAPSInt(CountExpr, C, ConstVal)) {
    unsigned Bits = getSizeTBits(C);
    uint64_t CV = ConstVal.getLimitedValue(UINT64_MAX);
    MaxCount = llvm::APInt(Bits, CV, /*isSigned=*/false);
    // Constants are safe to check; treat as constraint-derived for proof purposes.
    HasConstraintBound = true;
    return true;
  }

  SVal CountV = State->getSVal(CountExpr, LCtx);
  IsTainted = taint::isTainted(State, CountV);

  // Try to retrieve a symbol and ask the constraint manager for a path-sensitive upper bound.
  SymbolRef Sym = CountV.getAsSymbol();
  if (Sym) {
    Sym = stripCasts(Sym);

    if (const llvm::APSInt *MaxFromCM = inferSymbolMaxVal(Sym, C)) {
      unsigned Bits = getSizeTBits(C);
      uint64_t M = MaxFromCM->getLimitedValue(UINT64_MAX);
      MaxCount = llvm::APInt(Bits, M, /*isSigned=*/false);
      HasConstraintBound = true;
      // Also check our own bound map; take the tighter bound if available.
      auto Map = State->get<SymbolUpperBoundMap>();
      if (const llvm::APSInt *B = Map.lookup(Sym)) {
        uint64_t BM = B->getLimitedValue(UINT64_MAX);
        llvm::APInt BoundFromMap(Bits, BM, /*isSigned=*/false);
        if (BoundFromMap.ult(MaxCount))
          MaxCount = BoundFromMap;
      }
      return true;
    }

    // Consult our SymbolUpperBoundMap if CM doesn't return anything.
    auto Map = State->get<SymbolUpperBoundMap>();
    if (const llvm::APSInt *B = Map.lookup(Sym)) {
      unsigned Bits = getSizeTBits(C);
      uint64_t BM = B->getLimitedValue(UINT64_MAX);
      MaxCount = llvm::APInt(Bits, BM, /*isSigned=*/false);
      HasConstraintBound = true; // constraint-derived via our path tracking
      return true;
    }
  }

  // Fallback: use the integer type maximum as a conservative bound.
  QualType T = CountExpr->getType();
  if (T->isIntegerType()) {
    ASTContext &ACtx = C.getASTContext();
    unsigned TyBits = ACtx.getIntWidth(T);
    bool IsSignedTy = T->isSignedIntegerType();
    llvm::APInt TypeMax = IsSignedTy ? (llvm::APInt::getOneBitSet(TyBits, TyBits - 1) - 1)
                                     : llvm::APInt::getMaxValue(TyBits);
    unsigned SizeBits = getSizeTBits(C);
    MaxCount = TypeMax.zextOrTrunc(SizeBits);
    // This is not constraint-derived; keep HasConstraintBound as false.
    return true;
  }

  return false;
}

bool SAGenTestChecker::productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                                const llvm::APInt &MaxCount,
                                                CheckerContext &C) {
  if (ElemSizeBytes == 0)
    return true; // Degenerate: cannot overflow size_t
  unsigned Bits = getSizeTBits(C);
  llvm::APInt SizeMax = llvm::APInt::getMaxValue(Bits); // SIZE_MAX
  llvm::APInt Elem(Bits, ElemSizeBytes, /*isSigned=*/false);

  // threshold = SIZE_MAX / ElemSizeBytes
  llvm::APInt Threshold = SizeMax.udiv(Elem);
  return MaxCount.ule(Threshold);
}

bool SAGenTestChecker::isFalsePositive(const Expr *CountExpr, uint64_t ElemSizeBytes,
                                       CheckerContext &C, bool &IsTainted,
                                       bool &HasConstraintBound) {
  llvm::APInt MaxCount(/*bitWidth dummy*/1, 0);
  IsTainted = false;
  HasConstraintBound = false;

  if (!getUpperBoundForCount(CountExpr, C, MaxCount, HasConstraintBound, IsTainted)) {
    // Could not determine any bound; not enough information to prove safety.
    return false;
  }

  // If we can prove the product fits into size_t, it's safe — suppress warning.
  if (productProvablyFitsSizeT(ElemSizeBytes, MaxCount, C))
    return true;

  // Not provably safe -> keep for potential report.
  return false;
}

void SAGenTestChecker::report(const Expr *SizeE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Size is computed as sizeof(x) * count; use array_size() to avoid overflow", N);
  if (SizeE)
    R->addRange(SizeE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SizeIdx = 0;
  if (!isTargetFunction(Call, C, SizeIdx))
    return;

  if (SizeIdx >= Call.getNumArgs())
    return;

  const Expr *SizeE = Call.getArgExpr(SizeIdx);
  if (!SizeE)
    return;

  // If already using safe helpers, skip.
  if (ExprHasName(SizeE, "array_size", C) || ExprHasName(SizeE, "struct_size", C))
    return;

  const Expr *E = SizeE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  bool LIsSizeof = isSizeofExpr(L);
  bool RIsSizeof = isSizeofExpr(R);

  // We care about exactly one side being sizeof(...)
  if (LIsSizeof == RIsSizeof)
    return;

  const Expr *CountExpr = LIsSizeof ? R : L;
  const Expr *SizeofExpr = LIsSizeof ? L : R;

  if (!CountExpr || !SizeofExpr)
    return;

  // If count is a compile-time constant, skip (low risk).
  llvm::APSInt DummyConst;
  if (tryEvaluateToAPSInt(CountExpr, C, DummyConst))
    return;

  // Extract sizeof(...) in bytes.
  uint64_t ElemSizeBytes = 0;
  if (!getSizeofValueInBytes(SizeofExpr, C, ElemSizeBytes))
    return;

  // Suppress when we can prove no overflow in size_t given path constraints or type range.
  bool IsTainted = false;
  bool HasConstraintBound = false;
  if (isFalsePositive(CountExpr, ElemSizeBytes, C, IsTainted, HasConstraintBound)) {
    // Provably safe product.
    return;
  }

  // Not provably safe. To reduce false positives, require either:
  // - Count is tainted by user input, or
  // - We couldn't get any constraint-derived upper bound (i.e. unbounded/unknown).
  if (IsTainted || !HasConstraintBound) {
    report(SizeE, C);
  }
  // Else: we had a constraint-derived upper bound, but couldn't prove safety
  // and count is not tainted — suppress to avoid FPs on internal counts.
  return;
}

ProgramStateRef SAGenTestChecker::recordUpperBoundFromBinarySymExpr(
    ProgramStateRef State, const BinarySymExpr *BSE, bool Assumption,
    const ASTContext &AC) const {
  if (!BSE)
    return State;

  // Helper lambda: record S <= Bound into the map (keep tighter if existing).
  auto RecordUB = [&](ProgramStateRef St, SymbolRef S, const llvm::APSInt &Bound) -> ProgramStateRef {
    if (!S)
      return St;
    S = stripCasts(S);
    auto Map = St->get<SymbolUpperBoundMap>();
    const llvm::APSInt *Existing = Map.lookup(S);
    llvm::APSInt UB = Bound;
    if (Existing) {
      // Keep the tighter (minimum) bound.
      if (Existing->ule(UB))
        UB = *Existing;
    }
    auto &F = St->get_context<SymbolUpperBoundMap>();
    Map = F.add(Map, S, UB);
    return St->set<SymbolUpperBoundMap>(Map);
  };

  BinaryOperatorKind Op = BSE->getOpcode();

  // Case 1: Sym op Int
  if (const auto *SIE = dyn_cast<SymIntExpr>(BSE)) {
    SymbolRef S = SIE->getLHS();
    llvm::APSInt C = SIE->getRHS();
    // Normalize bound to size_t width for consistency.
    unsigned Bits = AC.getTypeSize(AC.getSizeType());
    C = C.extOrTrunc(Bits);
    C.setIsUnsigned(true);

    switch (Op) {
    case BO_GT:
      // (S > C) assumed false => S <= C
      if (!Assumption) return RecordUB(State, S, C);
      break;
    case BO_GE: {
      // (S >= C) assumed false => S < C => S <= C-1
      if (!Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        } else {
          // C == 0, S < 0 => for unsigned S no values; ignore
        }
      }
      break;
    }
    case BO_LT: {
      // (S < C) assumed true => S <= C-1
      if (Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        } else {
          // S < 0, ignore
        }
      }
      break;
    }
    case BO_LE:
      // (S <= C) assumed true => S <= C
      if (Assumption) return RecordUB(State, S, C);
      break;
    default:
      break;
    }
    return State;
  }

  // Case 2: Int op Sym
  if (const auto *ISE = dyn_cast<IntSymExpr>(BSE)) {
    llvm::APSInt C = ISE->getLHS();
    SymbolRef S = ISE->getRHS();
    unsigned Bits = AC.getTypeSize(AC.getSizeType());
    C = C.extOrTrunc(Bits);
    C.setIsUnsigned(true);

    switch (Op) {
    case BO_GT: {
      // (C > S), assumed true => S < C => S <= C-1
      if (Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    case BO_GE:
      // (C >= S), assumed true => S <= C
      if (Assumption) return RecordUB(State, S, C);
      break;
    case BO_LT:
      // (C < S), assumed false => C >= S => S <= C
      if (!Assumption) return RecordUB(State, S, C);
      break;
    case BO_LE: {
      // (C <= S), assumed false => C > S => S < C => S <= C-1
      if (!Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    default:
      break;
    }
    return State;
  }

  // Sym op Sym: ignore for now (no constant bound).
  return State;
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond,
                                             bool Assumption) const {
  // Only interested in relational symbolic expressions (NonLoc::SymbolVal over BinarySymExpr).
  if (auto NL = Cond.getAs<NonLoc>()) {
    if (auto SV = NL->getAs<nonloc::SymbolVal>()) {
      if (const SymExpr *SE = SV->getSymbol()) {
        if (const auto *BSE = dyn_cast<BinarySymExpr>(SE)) {
          const ASTContext &AC = State->getStateManager().getContext();
          return recordUpperBoundFromBinarySymExpr(State, BSE, Assumption, AC);
        }
      }
    }
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects open-coded sizeof(x) * count in size arguments; suggests array_size()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
