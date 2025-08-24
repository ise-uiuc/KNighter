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
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the framework context (see problem statement).
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};

// Assume there is a DerefTable defined somewhere else if used.
extern KnownDerefFunction DerefTable[];

bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    // Iterate until a sentinel entry with null Name is encountered.
    for (const KnownDerefFunction *Entry = DerefTable; Entry && Entry->Name; ++Entry) {
      if (FnName.equals(Entry->Name)) {
        DerefParams.append(Entry->Params.begin(), Entry->Params.end());
        return true;
      }
    }
  }
  return false;
}

bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Off-by-one bound check", "Logic")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  static StringRef getExprText(const Expr *E, CheckerContext &C) {
    if (!E)
      return StringRef();
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
    return Lexer::getSourceText(Range, SM, LangOpts);
  }

  static std::string normalizeNoSpace(StringRef S) {
    std::string Out;
    Out.reserve(S.size());
    for (char ch : S) {
      if (!isspace(static_cast<unsigned char>(ch)))
        Out.push_back(ch);
    }
    return Out;
  }

  static bool exprTextEqual(const Expr *A, const Expr *B, CheckerContext &C) {
    if (!A || !B) return false;
    StringRef TA = getExprText(A, C);
    StringRef TB = getExprText(B, C);
    if (TA.empty() || TB.empty()) return false;
    return normalizeNoSpace(TA) == normalizeNoSpace(TB);
  }

  static bool nameLooksLikeCountBound(StringRef Name) {
    std::string Lower = Name.lower();
    if (Lower.find("max") != std::string::npos)
      return true;
    if (Lower.find("limit") != std::string::npos || Lower.find("lim") != std::string::npos)
      return true;
    if (Lower.find("cap") != std::string::npos || Lower.find("capacity") != std::string::npos)
      return true;
    if (Lower.find("upper") != std::string::npos || Lower.find("bound") != std::string::npos)
      return true;
    if (Lower.find("count") != std::string::npos || Lower.find("num") != std::string::npos)
      return true;
    if (Lower.find("size") != std::string::npos || Lower.find("len") != std::string::npos)
      return true;
    return false;
  }

  static bool containsTimeLikeToken(StringRef S) {
    std::string L = S.lower().str();
    return L.find("period") != std::string::npos ||
           L.find("time") != std::string::npos ||
           L.find("timeout") != std::string::npos ||
           L.find("ns") != std::string::npos ||
           L.find("usec") != std::string::npos ||
           L.find("msec") != std::string::npos ||
           L.find("ms") != std::string::npos ||
           L.find("sec") != std::string::npos ||
           L.find("hz") != std::string::npos ||
           L.find("clock") != std::string::npos ||
           L.find("clk") != std::string::npos ||
           L.find("rate") != std::string::npos ||
           L.find("freq") != std::string::npos ||
           L.find("cycle") != std::string::npos;
  }

  static bool isDeclRefWithNameLikeCount(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *II = DRE->getDecl()->getIdentifier())
        return nameLooksLikeCountBound(II->getName());
      if (const NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(ME->getMemberDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    return false;
  }

  static bool isCompositeBoundExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    return !isa<DeclRefExpr>(E) && !isa<MemberExpr>(E) && !isa<IntegerLiteral>(E);
  }

  static bool isUnarySizeOf(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E))
      return U->getKind() == UETT_SizeOf;
    return false;
  }

  static bool isLikelyErrorReturn(const ReturnStmt *RS, CheckerContext &C) {
    if (!RS)
      return false;
    const Expr *RV = RS->getRetValue();
    if (!RV)
      return false;

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, RV, C))
      return Val.isSigned() ? Val.isNegative() : false;

    StringRef Txt = getExprText(RV, C);
    if (Txt.contains("-E") || Txt.contains("ERR_PTR") || Txt.contains("error") ||
        Txt.contains("-EINVAL") || Txt.contains("-EFAULT") || Txt.contains("-ENODATA") ||
        Txt.contains("-ENOLINK") || Txt.contains("-ENOLCK") || Txt.contains("-ERANGE"))
      return true;

    return false;
  }

  static bool thenBranchHasEarlyErrorReturn(const IfStmt *IS, CheckerContext &C) {
    if (!IS)
      return false;
    const Stmt *ThenS = IS->getThen();
    if (!ThenS)
      return false;
    const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
    if (!RS)
      return false;
    return isLikelyErrorReturn(RS, C);
  }

  // Check if an IntegerLiteral is spelled as a macro-like named constant.
  // E.g., RHS node is IntegerLiteral but source text contains an identifier like FOO_MAX.
  static bool isIntegerLiteralSpelledAsNamedBound(const Expr *E, CheckerContext &C) {
    const auto *IL = dyn_cast_or_null<IntegerLiteral>(E ? E->IgnoreParenCasts() : nullptr);
    if (!IL)
      return false;
    StringRef Txt = getExprText(E, C);
    if (Txt.empty())
      return false;

    // Allow typical numeric literal chars in integers: digits, hex prefix, and U/L suffixes.
    auto IsAllowedNumChar = [](char ch) {
      return (ch >= '0' && ch <= '9') ||
             (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') ||
             ch == 'x' || ch == 'X' || ch == 'u' || ch == 'U' || ch == 'l' || ch == 'L' ||
             ch == '\''; // digit separators
    };

    bool HasNonNumericToken = false;
    for (char ch : Txt) {
      if (isspace(static_cast<unsigned char>(ch)))
        continue;
      if (!IsAllowedNumChar(ch)) {
        HasNonNumericToken = true;
        break;
      }
    }

    if (!HasNonNumericToken)
      return false; // Pure numeric literal.

    // If it contains non-numeric token(s), check if it looks like a MAX-like named bound.
    return nameLooksLikeCountBound(Txt);
  }

  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    // Do not consider sizeof-style bounds.
    if (isUnarySizeOf(Bound))
      return false;

    // Named DeclRef/MemberExpr bound like FOO_MAX or obj.max_count.
    if (!isCompositeBoundExpr(Bound) && !isa<IntegerLiteral>(Bound))
      return isDeclRefWithNameLikeCount(Bound);

    // IntegerLiteral that is spelled via a named macro (e.g. RDS_MSG_RX_DGRAM_TRACE_MAX).
    if (isa<IntegerLiteral>(Bound))
      return isIntegerLiteralSpelledAsNamedBound(Bound, C);

    // Avoid complex expressions (e.g., ARRAY_SIZE(), a+b), to reduce FPs.
    return false;
  }

  static bool isLikelyIndexExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    // Index should be non-literal.
    if (isa<IntegerLiteral>(E))
      return false;

    // Prefer array-subscript style (most direct evidence of index usage).
    if (isa<ArraySubscriptExpr>(E))
      return true;

    // Also accept raw vars/fields which might be propagated indices.
    if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E))
      return true;

    return false;
  }

  static bool isBufferCapacityComparison(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    if (!LHS || !RHS)
      return false;

    if (isUnarySizeOf(RHS))
      return true;

    if (ExprHasName(LHS, "strlen", C) || ExprHasName(LHS, "strnlen", C))
      return true;

    return false;
  }

  // Specific false-positive filters for bit-width like "bits > 32".
  static bool containsBitsToken(StringRef S) {
    StringRef L = S.lower();
    return L.contains("bit") || L.contains("bits");
  }

  static bool isBitWidthStyleGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LT = getExprText(LHS, C);
    StringRef RT = getExprText(RHS, C);

    bool HasBitsToken = containsBitsToken(LT) || containsBitsToken(RT);

    // Common bit-width literals.
    bool RHSIsBitWidthLiteral = false;
    if (const auto *IL = dyn_cast_or_null<IntegerLiteral>(RHS ? RHS->IgnoreParenCasts() : nullptr)) {
      uint64_t V = IL->getValue().getLimitedValue();
      RHSIsBitWidthLiteral = (V == 8 || V == 16 || V == 32 || V == 64 || V == 128);
    }

    // Also consider calls with 'bits' in callee name.
    bool LHSCallHasBits = false;
    if (const auto *CE = dyn_cast_or_null<CallExpr>(LHS ? LHS->IgnoreParenCasts() : nullptr)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        if (const IdentifierInfo *II = FD->getIdentifier())
          LHSCallHasBits = containsBitsToken(II->getName());
      } else {
        // As a fallback, use source text.
        LHSCallHasBits = containsBitsToken(LT);
      }
    }

    return (HasBitsToken || LHSCallHasBits) && RHSIsBitWidthLiteral;
  }

  // FP filter: temporal/rate guards (period/time/clk/hz/rate/etc).
  static bool isTimeOrPeriodGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LT = getExprText(LHS, C);
    StringRef RT = getExprText(RHS, C);
    return containsTimeLikeToken(LT) || containsTimeLikeToken(RT);
  }

  // Find if the same LHS variable is also checked with a lower bound (var < min or var <= min)
  // within the same condition tree. This is commonly a value-range guard, not an index bound check.
  static bool hasLowerBoundForSameLHS(const Expr *RootCond, const Expr *TargetLHS, CheckerContext &C) {
    if (!RootCond || !TargetLHS)
      return false;

    RootCond = RootCond->IgnoreParenImpCasts();

    if (const auto *BO = dyn_cast<BinaryOperator>(RootCond)) {
      BinaryOperatorKind Op = BO->getOpcode();
      if (Op == BO_LT || Op == BO_LE) {
        if (exprTextEqual(BO->getLHS()->IgnoreParenCasts(), TargetLHS->IgnoreParenCasts(), C))
          return true;
      }
      // Traverse both sides for logical and other composed expressions.
      return hasLowerBoundForSameLHS(BO->getLHS(), TargetLHS, C) ||
             hasLowerBoundForSameLHS(BO->getRHS(), TargetLHS, C);
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(RootCond)) {
      return hasLowerBoundForSameLHS(CO->getCond(), TargetLHS, C) ||
             hasLowerBoundForSameLHS(CO->getTrueExpr(), TargetLHS, C) ||
             hasLowerBoundForSameLHS(CO->getFalseExpr(), TargetLHS, C);
    }

    return false;
  }

  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, const Expr *RootCond, CheckerContext &C) {
    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    // Exclude "x > MAX - 1" patterns; these are not our target in this checker.
    StringRef TxtR = getExprText(RHS, C);
    if (TxtR.contains("- 1") || TxtR.contains("-1"))
      return true;

    // Exclude bit-width style guards (e.g., "foo_bits(...) > 32").
    if (isBitWidthStyleGuard(LHS, RHS, C))
      return true;

    // Exclude time/period/rate style guards (e.g., "period_ns > max_period_ns").
    if (isTimeOrPeriodGuard(LHS, RHS, C))
      return true;

    // If RHS is a pure numeric literal (not macro-spelled), treat as FP.
    if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
      if (!isIntegerLiteralSpelledAsNamedBound(RHS, C))
        return true;
    }

    // If this '>' comparison is part of a range guard '(var < min || var > max)' on same LHS, exclude.
    if (hasLowerBoundForSameLHS(RootCond, LHS, C))
      return true;

    return false;
  }

  static void collectGtComparisons(const Expr *E,
                                   llvm::SmallVectorImpl<const BinaryOperator*> &Out) {
    if (!E)
      return;
    E = E->IgnoreParenImpCasts();

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
        collectGtComparisons(BO->getLHS(), Out);
        collectGtComparisons(BO->getRHS(), Out);
        return;
      }
      if (BO->getOpcode() == BO_GT) {
        Out.push_back(BO);
        return;
      }
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      collectGtComparisons(CO->getCond(), Out);
      collectGtComparisons(CO->getTrueExpr(), Out);
      collectGtComparisons(CO->getFalseExpr(), Out);
      return;
    }
  }

  bool isCandidateGtComparison(const BinaryOperator *BO, const Expr *RootCond, CheckerContext &C) const {
    if (!BO || BO->getOpcode() != BO_GT)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    if (!LHS || !RHS)
      return false;

    // LHS should look like an index or an index-bearing expression.
    if (!isLikelyIndexExpr(LHS))
      return false;

    // RHS should be a MAX-like bound (accept macro-spelled IntegerLiterals too).
    if (!isPlainMaxLikeBound(RHS, C))
      return false;

    // Avoid comparisons that are about buffer capacity/length, not indexing.
    if (isBufferCapacityComparison(LHS, RHS, C))
      return false;

    // Exclude known false positives (bit-width, time/rate, range-guard, etc.).
    if (isFalsePositive(LHS, RHS, RootCond, C))
      return false;

    return true;
  }
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<const BinaryOperator*, 4> GtComps;
  collectGtComparisons(CondE, GtComps);

  if (GtComps.empty())
    return;

  // The Then branch should look like an errno-style error path.
  if (!thenBranchHasEarlyErrorReturn(IS, C))
    return;

  for (const BinaryOperator *BO : GtComps) {
    if (!isCandidateGtComparison(BO, CondE, C))
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation",
        N);
    R->addRange(BO->getSourceRange());
    C.emitReport(std::move(R));
    // Report only once per If condition.
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one index validation using '>' instead of '>=' against MAX-like bounds",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 163 |     std::string L = S.lower().str();

	- Error Messages: ‘std::string’ {aka ‘class std::__cxx11::basic_string<char>’} has no member named ‘str’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
