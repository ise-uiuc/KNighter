Refinement Plan:
- Root cause: The checker treats any ArraySubscriptExpr on the left-hand side of “> MAX” as an index-like entity. In ALSA’s control code, the expression ucontrol->value.integer.value[0] is a scalar control value accessed via a fixed [0] array slot, not an index used to access arrays. The checker therefore mis-classifies a parameter bound validation (with inclusive bounds) as an index bound validation and fires on “> MAX”.
- Fixes:
  1. Refine index detection:
     - If LHS is an ArraySubscriptExpr with a constant subscript (e.g., [0]), do not treat it as index-like.
     - Suppress index-likeness for known “control value array” idioms (e.g., base path contains tokens like “ucontrol”, “control”, “kcontrol”, and “value”).
  2. Paired lower-bound suppression for array-subscript LHS:
     - If the “> MAX” comparison is part of a symmetric range check “X < MIN || X > MAX” for the same LHS expression and LHS is an ArraySubscriptExpr, suppress the report. This pattern strongly indicates scalar parameter validation with inclusive bounds, not array index checking.
     - Use a structural-expression equivalence routine to match the same LHS across the disjuncts.
  3. Keep existing true positives:
     - Do not suppress DeclRefExpr/MemberExpr LHS cases (e.g., idx or j) even if there is a lower bound check, because “idx < 0 || idx > MAX” remains an off-by-one bug we want to detect.
     - Keep detection for the target buggy code: LHS is trace.rx_trace_pos[i] (ArraySubscriptExpr with non-constant index), no paired lower-bound check exists; thus it will still be reported.
- Edge cases and regressions:
  - Excluding ArraySubscriptExpr with constant subscript reduces false positives for scalar parameter validations that use 1-element control arrays. Legit legitimate index problems do not use constant-subscript LHS.
  - The paired lower-bound suppression is limited to ArraySubscriptExpr LHS to avoid suppressing valid index-off-by-one reports when LHS is a scalar index variable.
- Clang-18 compatibility: The changes rely only on AST utilities and the provided helper patterns, no API changes or removed includes.

Refined Code:
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
#include <algorithm>
#include <string>
#include <cctype>

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

// The expression should be the DeclRefExpr of the array
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

  static std::string toLowerCopy(StringRef S) {
    std::string L = S.str();
    std::transform(L.begin(), L.end(), L.begin(), ::tolower);
    return L;
  }

  static bool nameLooksLikeCountBound(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
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
    return false;
  }

  static bool nameLooksLikeLengthOrSize(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("len") != std::string::npos ||
        Lower.find("length") != std::string::npos ||
        Lower.find("size") != std::string::npos ||
        Lower.find("nbytes") != std::string::npos ||
        Lower.find("bytes") != std::string::npos)
      return true;
    return false;
  }

  static bool nameLooksLikeCapacityOrMax(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("max_len") != std::string::npos ||
        Lower.find("maxlen") != std::string::npos ||
        Lower.find("max") != std::string::npos ||
        Lower.find("cap") != std::string::npos ||
        Lower.find("capacity") != std::string::npos ||
        Lower.find("space") != std::string::npos ||
        Lower.find("avail") != std::string::npos ||
        Lower.find("limit") != std::string::npos ||
        Lower.find("bound") != std::string::npos)
      return true;
    return false;
  }

  static bool looksLikeCountOrOrdinalName(StringRef Name) {
    if (Name.empty())
      return false;
    std::string L = toLowerCopy(Name);
    return (L.find("count") != std::string::npos ||
            L.find("num") != std::string::npos ||
            L.find("_nr") != std::string::npos ||
            L == "nr" || L == "cnt");
  }

  static bool looksLikeIndexName(StringRef Name) {
    if (Name.empty())
      return false;
    std::string L = toLowerCopy(Name);
    // Strong index-like tokens and common short loop indices.
    static const char *IndexToks[] = {
      "idx","index","ind","pos","slot","cursor","off","offset","ix"
    };
    for (const char *Tok : IndexToks)
      if (L.find(Tok) != std::string::npos)
        return true;
    // Single-letter loop indices are also index-like.
    if (L == "i" || L == "j" || L == "k")
      return true;
    return false;
  }

  static StringRef getIdentNameFromExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return StringRef();

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *I = DRE->getDecl()->getIdentifier())
        return I->getName();
      if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
        return ND->getName();
    }
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(ME->getMemberDecl()))
        return ND->getName();
    }
    return StringRef();
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
        Txt.contains("-ENOLINK") || Txt.contains("-ENOLCK") || Txt.contains("-ERANGE") ||
        Txt.contains("-ENAMETOOLONG") || Txt.contains("-ENOKEY"))
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

  static bool rhsTextLooksMaxLike(const Expr *RHS, CheckerContext &C) {
    StringRef Txt = getExprText(RHS, C);
    std::string L = toLowerCopy(Txt);
    return (!L.empty() &&
            (L.find("max") != std::string::npos ||
             L.find("limit") != std::string::npos ||
             L.find("bound") != std::string::npos));
  }

  static bool rhsTextLooksMinLike(const Expr *RHS, CheckerContext &C) {
    StringRef Txt = getExprText(RHS, C);
    std::string L = toLowerCopy(Txt);
    return (!L.empty() &&
            (L.find("min") != std::string::npos ||
             L.find("start") != std::string::npos ||
             L.find("lower") != std::string::npos ||
             L.find("lo") != std::string::npos ||
             L.find("begin") != std::string::npos ||
             L.find("first") != std::string::npos));
  }

  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    if (isa<IntegerLiteral>(Bound)) {
      return rhsTextLooksMaxLike(Bound, C);
    }

    if (isUnarySizeOf(Bound))
      return false;

    if (isCompositeBoundExpr(Bound))
      return false;

    StringRef Name = getIdentNameFromExpr(Bound);
    if (!Name.empty())
      return nameLooksLikeCapacityOrMax(Name); // Do not treat *_count/*_num as MAX-like.

    return rhsTextLooksMaxLike(Bound, C);
  }

  static bool isPlainMinLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    if (isa<IntegerLiteral>(Bound)) {
      return rhsTextLooksMinLike(Bound, C);
    }

    if (isUnarySizeOf(Bound))
      return false;

    if (isCompositeBoundExpr(Bound))
      return false;

    StringRef Name = getIdentNameFromExpr(Bound);
    if (!Name.empty())
      return rhsTextLooksMinLike(Bound, C);

    return rhsTextLooksMinLike(Bound, C);
  }

  // Range endpoint detection helpers.

  static bool hasUnderscoreToken(StringRef Name, StringRef Tok) {
    SmallVector<StringRef, 8> Parts;
    Name.split(Parts, '_', -1, false);
    for (StringRef P : Parts)
      if (P.equals_insensitive(Tok))
        return true;
    return false;
  }

  static bool nameHasPrefixToken(StringRef Name, StringRef Tok) {
    StringRef L = StringRef(toLowerCopy(Name));
    std::string Prefix = (Tok + "_").str();
    return L.startswith(Prefix);
  }

  static bool nameHasSuffixToken(StringRef Name, StringRef Tok) {
    StringRef L = StringRef(toLowerCopy(Name));
    std::string Suffix = ("_" + Tok).str();
    return L.endswith(Suffix);
  }

  static bool nameHasTokenMin(StringRef Name) {
    return hasUnderscoreToken(Name, "min") || nameHasPrefixToken(Name, "min") || nameHasSuffixToken(Name, "min") ||
           hasUnderscoreToken(Name, "start") || nameHasPrefixToken(Name, "start") || nameHasSuffixToken(Name, "start") ||
           hasUnderscoreToken(Name, "begin") || nameHasPrefixToken(Name, "begin") || nameHasSuffixToken(Name, "begin") ||
           hasUnderscoreToken(Name, "first") || nameHasPrefixToken(Name, "first") || nameHasSuffixToken(Name, "first") ||
           hasUnderscoreToken(Name, "lo") || hasUnderscoreToken(Name, "low") || hasUnderscoreToken(Name, "lower");
  }

  static bool nameHasTokenMax(StringRef Name) {
    return hasUnderscoreToken(Name, "max") || nameHasPrefixToken(Name, "max") || nameHasSuffixToken(Name, "max") ||
           hasUnderscoreToken(Name, "end") || nameHasPrefixToken(Name, "end") || nameHasSuffixToken(Name, "end") ||
           hasUnderscoreToken(Name, "last") || nameHasPrefixToken(Name, "last") || nameHasSuffixToken(Name, "last") ||
           hasUnderscoreToken(Name, "hi") || hasUnderscoreToken(Name, "high") || hasUnderscoreToken(Name, "upper");
  }

  static std::string stripRangeEndpointTokens(StringRef Name) {
    std::string L = toLowerCopy(Name);
    auto stripPrefix = [&](const char *Tok) {
      std::string P = std::string(Tok) + "_";
      if (L.rfind(P, 0) == 0) // startswith
        L.erase(0, P.size());
    };
    auto stripSuffix = [&](const char *Tok) {
      std::string S = std::string("_") + Tok;
      if (L.size() >= S.size() && L.compare(L.size() - S.size(), S.size(), S) == 0)
        L.erase(L.size() - S.size());
    };
    const char *MinToks[] = {"min","start","begin","first","lo","low","lower"};
    const char *MaxToks[] = {"max","end","last","hi","high","upper"};

    for (const char *T : MinToks) { stripPrefix(T); stripSuffix(T); }
    for (const char *T : MaxToks) { stripPrefix(T); stripSuffix(T); }
    return L;
  }

  static bool textHasMaxLike(StringRef Text) {
    StringRef L = StringRef(toLowerCopy(Text));
    return L.contains("max") || L.contains("end") || L.contains("last") || L.contains("upper") || L.contains("hi") || L.contains("high");
  }

  static bool rhsHasMaxTokenOrText(const Expr *RHS, CheckerContext &C) {
    StringRef RName = getIdentNameFromExpr(RHS);
    if (!RName.empty() && nameHasTokenMax(RName))
      return true;
    return rhsTextLooksMaxLike(RHS, C) || textHasMaxLike(getExprText(RHS, C));
  }

  // Detects comparisons of the form "min_* > max_*" on the same base, which are range guards.
  static bool isMinMaxRangeGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    if (LName.empty() || RName.empty())
      return false;

    if (!(nameHasTokenMin(LName) && nameHasTokenMax(RName)))
      return false;

    std::string LBase = stripRangeEndpointTokens(LName);
    std::string RBase = stripRangeEndpointTokens(RName);
    if (!LBase.empty() && !RBase.empty() && LBase == RBase)
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

    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    if ((!LName.empty() && nameLooksLikeLengthOrSize(LName)) &&
        ((!RName.empty() && nameLooksLikeCapacityOrMax(RName)) || rhsTextLooksMaxLike(RHS, C)))
      return true;

    if ((LName.equals_insensitive("len") || LName.equals_insensitive("length") || LName.equals_insensitive("size")) &&
        rhsTextLooksMaxLike(RHS, C))
      return true;

    return false;
  }

  static bool containsBitsToken(StringRef S) {
    std::string L = S.lower();
    auto has = [&](const char *Tok){ return L.find(Tok) != std::string::npos; };
    return has("bit") || has("bits");
  }

  static bool isBitWidthStyleGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LT = getExprText(LHS, C);
    StringRef RT = getExprText(RHS, C);

    bool HasBitsToken = containsBitsToken(LT) || containsBitsToken(RT);

    bool RHSIsBitWidthLiteral = false;
    if (const auto *IL = dyn_cast_or_null<IntegerLiteral>(RHS ? RHS->IgnoreParenCasts() : nullptr)) {
      uint64_t V = IL->getValue().getLimitedValue();
      RHSIsBitWidthLiteral = (V == 8 || V == 16 || V == 32 || V == 64 || V == 128);
    }

    bool LHSCallHasBits = false;
    if (const auto *CE = dyn_cast_or_null<CallExpr>(LHS ? LHS->IgnoreParenCasts() : nullptr)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        if (const IdentifierInfo *II = FD->getIdentifier())
          LHSCallHasBits = containsBitsToken(II->getName());
      } else {
        LHSCallHasBits = containsBitsToken(LT);
      }
    }

    return (HasBitsToken || LHSCallHasBits) && RHSIsBitWidthLiteral;
  }

  static bool looksLikeEnumFieldName(StringRef Name) {
    if (Name.empty())
      return false;
    if (Name.equals_insensitive("id") ||
        Name.equals_insensitive("type") ||
        Name.equals_insensitive("mode") ||
        Name.equals_insensitive("state") ||
        Name.equals_insensitive("kind") ||
        Name.equals_insensitive("class") ||
        Name.equals_insensitive("family") ||
        Name.equals_insensitive("proto") ||
        Name.equals_insensitive("protocol") ||
        Name.equals_insensitive("prio") ||
        Name.equals_insensitive("level") ||
        Name.equals_insensitive("opcode") ||
        Name.equals_insensitive("op"))
      return true;

    if (hasUnderscoreToken(Name, "id") ||
        hasUnderscoreToken(Name, "type") ||
        hasUnderscoreToken(Name, "mode") ||
        hasUnderscoreToken(Name, "state") ||
        hasUnderscoreToken(Name, "kind") ||
        hasUnderscoreToken(Name, "class") ||
        hasUnderscoreToken(Name, "family") ||
        hasUnderscoreToken(Name, "proto") ||
        hasUnderscoreToken(Name, "protocol") ||
        hasUnderscoreToken(Name, "prio") ||
        hasUnderscoreToken(Name, "level") ||
        hasUnderscoreToken(Name, "opcode") ||
        hasUnderscoreToken(Name, "op"))
      return true;

    return false;
  }

  static bool looksLikeEnumMaxNameOrText(StringRef NOrText) {
    if (NOrText.empty())
      return false;
    StringRef L = NOrText.lower();
    if (L.contains("id_max"))
      return true;

    static constexpr const char *EnumTokens[] = {
        "id","type","mode","state","kind","class","family","proto","protocol","prio","level","opcode","op"
    };
    for (const char *Tok : EnumTokens) {
      std::string pat1 = std::string(Tok) + "_max";
      std::string pat2 = std::string("max_") + Tok;
      if (L.contains(pat1) || L.contains(pat2))
        return true;
    }

    if ((L.contains("max") && hasUnderscoreToken(NOrText, "id")) ||
        (L.contains("id") && L.contains("max")))
      return true;

    return false;
  }

  static bool isEnumIdMaxGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    StringRef RText = getExprText(RHS, C); // Use source text to catch macros that expand to literals.

    bool LLooksEnum = looksLikeEnumFieldName(LName);
    bool RLooksEnumMax = looksLikeEnumMaxNameOrText(RName) || looksLikeEnumMaxNameOrText(RText);
    return LLooksEnum && RLooksEnumMax;
  }

  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    if (isa<IntegerLiteral>(R) && !rhsTextLooksMaxLike(RHS, C)) {
      return true;
    }

    StringRef TxtR = getExprText(RHS, C);
    if (TxtR.contains("- 1") || TxtR.contains("-1"))
      return true;

    if (isBitWidthStyleGuard(LHS, RHS, C))
      return true;

    if (isEnumIdMaxGuard(LHS, RHS, C))
      return true;

    // New: Exclude "min vs max" range validity guards.
    if (isMinMaxRangeGuard(LHS, RHS, C))
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

  static void collectLtLeComparisons(const Expr *E,
                                     llvm::SmallVectorImpl<const BinaryOperator*> &Out) {
    if (!E)
      return;
    E = E->IgnoreParenImpCasts();

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
        collectLtLeComparisons(BO->getLHS(), Out);
        collectLtLeComparisons(BO->getRHS(), Out);
        return;
      }
      if (BO->getOpcode() == BO_LT || BO->getOpcode() == BO_LE) {
        Out.push_back(BO);
        return;
      }
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      collectLtLeComparisons(CO->getCond(), Out);
      collectLtLeComparisons(CO->getTrueExpr(), Out);
      collectLtLeComparisons(CO->getFalseExpr(), Out);
      return;
    }
  }

  static const Decl* getReferencedDecl(const Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      return DRE->getDecl()->getCanonicalDecl();
    if (const auto *ME = dyn_cast<MemberExpr>(E))
      return ME->getMemberDecl()->getCanonicalDecl();
    return nullptr;
  }

  static bool sameReferencedVar(const Expr *A, const Expr *B) {
    const Decl *DA = getReferencedDecl(A);
    const Decl *DB = getReferencedDecl(B);
    return DA && DB && (DA == DB);
  }

  static bool isIntLiteralEqual(const Expr *E, unsigned V) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E) return false;
    if (const auto *IL = dyn_cast<IntegerLiteral>(E))
      return IL->getValue() == V;
    return false;
  }

  // Structural equality for expressions used to compare if two LHS expressions are the "same".
  static bool areEquivalentExprs(const Expr *A, const Expr *B, CheckerContext &C) {
    if (!A || !B) return false;
    A = A->IgnoreParenCasts();
    B = B->IgnoreParenCasts();

    if (A == B) return true;

    if (const auto *DA = dyn_cast<DeclRefExpr>(A)) {
      if (const auto *DB = dyn_cast<DeclRefExpr>(B))
        return DA->getDecl()->getCanonicalDecl() == DB->getDecl()->getCanonicalDecl();
    }

    if (const auto *MA = dyn_cast<MemberExpr>(A)) {
      if (const auto *MB = dyn_cast<MemberExpr>(B)) {
        if (MA->getMemberDecl()->getCanonicalDecl() != MB->getMemberDecl()->getCanonicalDecl())
          return false;
        return areEquivalentExprs(MA->getBase(), MB->getBase(), C);
      }
    }

    if (const auto *AA = dyn_cast<ArraySubscriptExpr>(A)) {
      if (const auto *AB = dyn_cast<ArraySubscriptExpr>(B)) {
        return areEquivalentExprs(AA->getBase(), AB->getBase(), C) &&
               areEquivalentExprs(AA->getIdx(), AB->getIdx(), C);
      }
    }

    if (const auto *UA = dyn_cast<UnaryOperator>(A)) {
      if (const auto *UB = dyn_cast<UnaryOperator>(B)) {
        if (UA->getOpcode() != UB->getOpcode())
          return false;
        return areEquivalentExprs(UA->getSubExpr(), UB->getSubExpr(), C);
      }
    }

    // Fallback to textual match for common simple cases (macros, etc.).
    StringRef TA = getExprText(A, C);
    StringRef TB = getExprText(B, C);
    return !TA.empty() && TA == TB;
  }

  // Detect if the current '>' comparison on an ArraySubscriptExpr LHS is paired with a lower-bound guard (x < MIN).
  static bool hasPairedLowerBoundGuardForArrayLHS(const Expr *FullCond, const Expr *LHSCand, CheckerContext &C) {
    const auto *ASE = dyn_cast_or_null<ArraySubscriptExpr>(LHSCand ? LHSCand->IgnoreParenCasts() : nullptr);
    if (!ASE || !FullCond)
      return false;

    llvm::SmallVector<const BinaryOperator*, 8> LtComps;
    collectLtLeComparisons(FullCond, LtComps);

    for (const BinaryOperator *BO : LtComps) {
      const Expr *L = BO->getLHS()->IgnoreParenCasts();
      const Expr *R = BO->getRHS()->IgnoreParenCasts();

      if (!areEquivalentExprs(L, ASE, C))
        continue;

      // RHS named MIN-like, or small integer literal (0/1)
      bool MinLike = isPlainMinLikeBound(R, C);
      if (!MinLike) {
        if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
          uint64_t V = IL->getValue().getLimitedValue();
          if (V <= 1)
            MinLike = true;
        }
      }
      if (MinLike)
        return true;
    }
    return false;
  }

  // Recognize scalar-control-style one-element array access (e.g., ucontrol->value.integer.value[0]).
  static bool isControlValueArrayAccess(const ArraySubscriptExpr *ASE, CheckerContext &C) {
    if (!ASE) return false;
    const Expr *Idx = ASE->getIdx()->IgnoreParenCasts();
    if (!isa<IntegerLiteral>(Idx))
      return false;

    uint64_t V = cast<IntegerLiteral>(Idx)->getValue().getLimitedValue();
    if (V != 0)
      return false;

    // Heuristic: base expression text contains tokens like 'ucontrol'/'control' and 'value'.
    StringRef BaseTxt = getExprText(ASE->getBase(), C);
    std::string L = toLowerCopy(BaseTxt);
    bool HasControlTok = (L.find("ucontrol") != std::string::npos) ||
                         (L.find("kcontrol") != std::string::npos) ||
                         (L.find("control") != std::string::npos) ||
                         (L.find("ctl") != std::string::npos);
    bool HasValueTok = (L.find("value") != std::string::npos) ||
                        (L.find("val") != std::string::npos);
    return HasControlTok && HasValueTok;
  }

  // Detect the 1-based ordinal guard pattern for the same LHS symbol:
  // "!x" or "x == 0" or "x <= 0" or "x < 1"
  static bool hasZeroOrOneGuardForVar(const Expr *E, const Expr *LHSVar, CheckerContext &C) {
    if (!E || !LHSVar) return false;
    E = E->IgnoreParenImpCasts();

    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_LNot) {
        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (sameReferencedVar(Sub, LHSVar))
          return true;
      }
      return hasZeroOrOneGuardForVar(UO->getSubExpr(), LHSVar, C);
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      BinaryOperatorKind Op = BO->getOpcode();
      if (Op == BO_LAnd || Op == BO_LOr) {
        return hasZeroOrOneGuardForVar(BO->getLHS(), LHSVar, C) ||
               hasZeroOrOneGuardForVar(BO->getRHS(), LHSVar, C);
      }

      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      auto checkVarZero = [&](const Expr *VarSide, const Expr *OtherSide, BinaryOperatorKind Op2) -> bool {
        if (!sameReferencedVar(VarSide, LHSVar))
          return false;
        if (Op2 == BO_EQ && isIntLiteralEqual(OtherSide, 0))
          return true;
        if (Op2 == BO_LE && isIntLiteralEqual(OtherSide, 0))
          return true;
        if (Op2 == BO_LT && isIntLiteralEqual(OtherSide, 1))
          return true;
        return false;
      };

      if (checkVarZero(L, R, Op) || checkVarZero(R, L, Op))
        return true;

      return hasZeroOrOneGuardForVar(BO->getLHS(), LHSVar, C) ||
             hasZeroOrOneGuardForVar(BO->getRHS(), LHSVar, C);
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      return hasZeroOrOneGuardForVar(CO->getCond(), LHSVar, C) ||
             hasZeroOrOneGuardForVar(CO->getTrueExpr(), LHSVar, C) ||
             hasZeroOrOneGuardForVar(CO->getFalseExpr(), LHSVar, C);
    }

    return false;
  }

  // Enhanced to use RHS context for range-endpoint suppression.
  static bool isLikelyIndexExpr(const Expr *E, const Expr *RHSForContext = nullptr, CheckerContext *PCtx = nullptr) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (isa<IntegerLiteral>(E))
      return false;

    // Array indexing is typically index-like, but exclude scalar-control idioms.
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      // Exclude constant-subscript forms like arr[0].
      const Expr *Idx = ASE->getIdx()->IgnoreParenCasts();
      if (isa<IntegerLiteral>(Idx))
        return false;

      // Exclude "ucontrol/kcontrol/...->value[0]" style scalar control arrays.
      if (isControlValueArrayAccess(ASE, *PCtx))
        return false;

      // If base's terminal name is 'value' or 'val', likely not an index.
      StringRef BaseName = getIdentNameFromExpr(ASE->getBase());
      if (BaseName.equals_insensitive("value") || BaseName.equals_insensitive("val"))
        return false;

      return true;
    }

    StringRef Name = getIdentNameFromExpr(E);
    if (!Name.empty()) {
      if (nameLooksLikeLengthOrSize(Name))
        return false;
      // New: exclude count/ordinal-like names from being treated as indices.
      if (looksLikeCountOrOrdinalName(Name))
        return false;
      // If LHS name looks like a range "min/start/lo" endpoint, and RHS is max-like, suppress.
      if (nameHasTokenMin(Name)) {
        if (RHSForContext && PCtx) {
          if (rhsHasMaxTokenOrText(RHSForContext, *PCtx))
            return false;
        }
      }
    }

    if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E))
      return true;

    return false;
  }

  // Helper: does expression E reference the given VarDecl (by DeclRefExpr)?
  static bool exprReferencesVar(const Expr *E, const Decl *Var) {
    if (!E || !Var) return false;
    E = E->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      return DRE->getDecl()->getCanonicalDecl() == Var->getCanonicalDecl();
    }
    for (const Stmt *Child : E->children()) {
      if (!Child) continue;
      if (const auto *CE = dyn_cast<Expr>(Child))
        if (exprReferencesVar(CE, Var))
          return true;
    }
    return false;
  }

  // Recursively search for array subscript expressions where 'Var' is used as index.
  static bool stmtContainsIndexUseOfVar(const Stmt *S, const Decl *Var) {
    if (!S || !Var) return false;
    if (const auto *E = dyn_cast<Expr>(S)) {
      const Expr *EI = E->IgnoreParenCasts();
      if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(EI)) {
        const Expr *Idx = ASE->getIdx()->IgnoreParenCasts();
        if (exprReferencesVar(Idx, Var))
          return true;
      }
    }
    for (const Stmt *Child : S->children()) {
      if (Child && stmtContainsIndexUseOfVar(Child, Var))
        return true;
    }
    return false;
  }

  // Search subsequent statements in the same enclosing compound for 'arr[var]' usage.
  static bool varUsedAsIndexAfterIf(const IfStmt *IS, const Decl *Var, CheckerContext &C) {
    if (!IS || !Var) return false;
    const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
    if (!CS) return false;
    bool SeenIf = false;
    for (const Stmt *S : CS->body()) {
      if (!SeenIf) {
        if (S == IS)
          SeenIf = true;
        continue;
      }
      if (!S) continue;
      if (stmtContainsIndexUseOfVar(S, Var))
        return true;
    }
    return false;
  }

  // Recursively search for assignments of the form "count_like_target = Var".
  static bool stmtHasCountLikeAssignmentFromVar(const Stmt *S, const Decl *Var) {
    if (!S || !Var) return false;
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->isAssignmentOp()) {
        const Expr *L = BO->getLHS()->IgnoreParenCasts();
        const Expr *R = BO->getRHS()->IgnoreParenCasts();
        if (exprReferencesVar(R, Var)) {
          StringRef LName = getIdentNameFromExpr(L);
          if (!LName.empty() && looksLikeCountOrOrdinalName(LName))
            return true;
        }
      }
    }
    for (const Stmt *Child : S->children()) {
      if (Child && stmtHasCountLikeAssignmentFromVar(Child, Var))
        return true;
    }
    return false;
  }

  // Search subsequent statements in the same enclosing compound for "count_like = Var".
  static bool flowsIntoCountLikeAfterIf(const IfStmt *IS, const Decl *Var, CheckerContext &C) {
    if (!IS || !Var) return false;
    const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
    if (!CS) return false;
    bool SeenIf = false;
    for (const Stmt *S : CS->body()) {
      if (!SeenIf) {
        if (S == IS)
          SeenIf = true;
        continue;
      }
      if (!S) continue;
      if (stmtHasCountLikeAssignmentFromVar(S, Var))
        return true;
    }
    return false;
  }

  bool isCandidateGtComparison(const BinaryOperator *BO, const IfStmt *EnclosingIf, const Expr *FullCond, CheckerContext &C) const {
    if (!BO || BO->getOpcode() != BO_GT)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    if (!LHS || !RHS)
      return false;

    // LHS should look like an index. Exclude size/len fields and min/max range endpoints.
    if (!isLikelyIndexExpr(LHS, RHS, &C))
      return false;

    // Special suppression: if LHS is an ArraySubscriptExpr and the full condition also
    // contains a paired lower-bound check on the same LHS (x < MIN), this is likely a
    // scalar parameter range validation, not index validation.
    if (hasPairedLowerBoundGuardForArrayLHS(FullCond, LHS, C))
      return false;

    // RHS should be a named MAX-like bound (including macros that expand to integers).
    if (!isPlainMaxLikeBound(RHS, C))
      return false;

    // Avoid comparisons that are about buffer capacity/length, not indexing.
    if (isBufferCapacityComparison(LHS, RHS, C))
      return false;

    // Exclude known false positives (e.g., bit-width checks, enum ID guards, min/max range).
    if (isFalsePositive(LHS, RHS, C))
      return false;

    // Additional suppression to avoid count-setting false positives:
    // If LHS is a plain variable (not an array subscript), require it to either:
    //  - be strongly index-like by name, or
    //  - be used as an array index later in the same scope after the 'if'.
    // Also, suppress if it clearly flows into a count-like assignment later.
    if (!isa<ArraySubscriptExpr>(LHS)) {
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        const Decl *Var = DRE->getDecl()->getCanonicalDecl();
        StringRef LName = getIdentNameFromExpr(LHS);
        bool StrongIndexName = looksLikeIndexName(LName);

        bool UsedAsIndexLater = varUsedAsIndexAfterIf(EnclosingIf, Var, C);
        bool FlowsToCount = flowsIntoCountLikeAfterIf(EnclosingIf, Var, C);

        // If this value is used to set a count-like field, treat this as capacity validation, not index validation.
        if (FlowsToCount)
          return false;

        // If not strongly index-like and not used later as an index, suppress.
        if (!StrongIndexName && !UsedAsIndexLater)
          return false;
      }
    }

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
    if (!isCandidateGtComparison(BO, IS, CondE, C))
      continue;

    // Suppress the common 1-based ordinal check: (!x || x == 0/<=0/<1) || (x > Bound)
    if (hasZeroOrOneGuardForVar(CondE, BO->getLHS(), C))
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
