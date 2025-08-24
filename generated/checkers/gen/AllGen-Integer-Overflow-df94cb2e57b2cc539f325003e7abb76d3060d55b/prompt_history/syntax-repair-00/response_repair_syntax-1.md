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
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "llvm/ADT/StringRef.h"
#include <utility>
#include <vector>
#include <memory>
#include <cctype>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ReportedRegions, const MemRegion *, char)

namespace {

class SAGenTestChecker : public Checker<check::Bind, check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Sector count truncation/format mismatch", "Integer bugs")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Helpers for truncation detection
      static bool isSectorLikeName(StringRef N);
      static bool isUnsigned32(QualType T, ASTContext &Ctx);
      static bool isInt64OrWider(QualType T, ASTContext &Ctx);
      static const Expr* getRHSExprFromStmt(const Stmt *S);
      static std::pair<const MemRegion*, const VarDecl*> getDestRegionAndDecl(SVal Loc, CheckerContext &C);
      static bool exprOrStmtMentionsMinTU64(const Stmt *S, CheckerContext &C);
      static bool wasAlreadyReported(const MemRegion *R, CheckerContext &C);
      static void markReported(const MemRegion *R, CheckerContext &C);

      // Helpers for printf-like checking
      static bool getPrintfLikeInfo(const CallEvent &Call, CheckerContext &C, unsigned &FmtIndex, const StringLiteral *&FmtSL);
      static void parseFormatString(StringRef Fmt, struct ASTContext &Ctx,
                                    std::vector<std::pair<bool/*hasLL*/, bool/*hasSingleL*/>> &ConvMods,
                                    std::vector<char> &ConvChars);
      static bool isIntegerConvChar(char C);
      static bool argLooksSectorLike(const Expr *E, CheckerContext &C);
};

// ---- Helper implementations ----

bool SAGenTestChecker::isSectorLikeName(StringRef N) {
  // Case-insensitive contains checks for sector/reserved terminology
  return N.contains_insensitive("sector") ||
         N.contains_insensitive("sectors") ||
         N.contains_insensitive("disk_res") ||
         N.contains_insensitive("reserved") ||
         N.contains_insensitive("sectors_free");
}

bool SAGenTestChecker::isUnsigned32(QualType T, ASTContext &Ctx) {
  if (T.isNull())
    return false;
  if (!T->isIntegerType())
    return false;
  if (!T->isUnsignedIntegerType())
    return false;
  unsigned W = Ctx.getTypeSize(T);
  return W <= 32;
}

bool SAGenTestChecker::isInt64OrWider(QualType T, ASTContext &Ctx) {
  if (T.isNull())
    return false;
  if (!T->isIntegerType())
    return false;
  unsigned W = Ctx.getTypeSize(T);
  return W >= 64;
}

std::pair<const MemRegion*, const VarDecl*>
SAGenTestChecker::getDestRegionAndDecl(SVal Loc, CheckerContext &C) {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return {nullptr, nullptr};
  R = R->getBaseRegion();
  if (!R)
    return {nullptr, nullptr};
  if (const auto *VR = dyn_cast<VarRegion>(R)) {
    const VarDecl *VD = dyn_cast<VarDecl>(VR->getDecl());
    return {R, VD};
  }
  return {R, nullptr};
}

const Expr* SAGenTestChecker::getRHSExprFromStmt(const Stmt *S) {
  if (!S)
    return nullptr;
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      return BO->getRHS();
  } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    if (DS->isSingleDecl()) {
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (VD->hasInit())
          return VD->getInit();
      }
    }
  }
  return nullptr;
}

bool SAGenTestChecker::exprOrStmtMentionsMinTU64(const Stmt *S, CheckerContext &C) {
  if (!S)
    return false;
  const Expr *E = getRHSExprFromStmt(S);
  if (!E)
    E = findSpecificTypeInChildren<Expr>(S);
  if (!E)
    return false;
  // Look for textual macro name and type token
  if (ExprHasName(E, "min_t(", C) && ExprHasName(E, "u64", C))
    return true;
  return false;
}

bool SAGenTestChecker::wasAlreadyReported(const MemRegion *R, CheckerContext &C) {
  if (!R)
    return false;
  ProgramStateRef St = C.getState();
  const char *P = St->get<ReportedRegions>(R);
  return P != nullptr;
}

void SAGenTestChecker::markReported(const MemRegion *R, CheckerContext &C) {
  if (!R)
    return;
  ProgramStateRef St = C.getState();
  St = St->set<ReportedRegions>(R, 1);
  C.addTransition(St);
}

// Printf-like helpers
bool SAGenTestChecker::getPrintfLikeInfo(const CallEvent &Call, CheckerContext &C,
                                         unsigned &FmtIndex, const StringLiteral *&FmtSL) {
  FmtSL = nullptr;
  FmtIndex = 0;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Recognize a small set of known functions:
  bool IsPrintk = ExprHasName(Origin, "printk", C);
  bool IsBchInconsistent = ExprHasName(Origin, "bch2_trans_inconsistent", C);

  if (!IsPrintk && !IsBchInconsistent)
    return false;

  if (IsPrintk)
    FmtIndex = 0; // printk(const char *fmt, ...)
  if (IsBchInconsistent)
    FmtIndex = 1; // bch2_trans_inconsistent(trans, const char *fmt, ...)

  if (Call.getNumArgs() <= FmtIndex)
    return false;

  const Expr *FmtExpr = Call.getArgExpr(FmtIndex);
  if (!FmtExpr)
    return false;

  FmtSL = dyn_cast<StringLiteral>(FmtExpr->IgnoreImpCasts());
  if (!FmtSL)
    return false;

  return true;
}

bool SAGenTestChecker::isIntegerConvChar(char C) {
  switch (C) {
    case 'd': case 'i': case 'u': case 'o': case 'x': case 'X':
      return true;
    default:
      return false;
  }
}

void SAGenTestChecker::parseFormatString(StringRef Fmt, ASTContext &Ctx,
                                         std::vector<std::pair<bool,bool>> &ConvMods,
                                         std::vector<char> &ConvChars) {
  // Very lightweight parser:
  // Collect conversions, record if they carry 'll' or single 'l'
  for (size_t i = 0, e = Fmt.size(); i < e; ++i) {
    if (Fmt[i] != '%')
      continue;
    ++i;
    if (i >= e) break;
    if (Fmt[i] == '%') // "%%"
      continue;

    // Skip flags
    while (i < e && (Fmt[i] == '-' || Fmt[i] == '+' || Fmt[i] == ' ' ||
                     Fmt[i] == '#' || Fmt[i] == '0')) {
      ++i;
    }

    // Skip field width
    if (i < e && Fmt[i] == '*') {
      ++i;
    } else {
      while (i < e && isdigit(Fmt[i]))
        ++i;
    }

    // Skip precision
    if (i < e && Fmt[i] == '.') {
      ++i;
      if (i < e && Fmt[i] == '*') {
        ++i;
      } else {
        while (i < e && isdigit(Fmt[i]))
          ++i;
      }
    }

    // Length modifiers: we only care about l/ll (others ignored)
    bool hasLL = false;
    bool hasL = false;

    if (i + 1 < e && Fmt[i] == 'l' && Fmt[i+1] == 'l') {
      hasLL = true;
      i += 2;
    } else if (i < e && Fmt[i] == 'l') {
      hasL = true;
      i += 1;
    } else if (i < e && (Fmt[i] == 'z' || Fmt[i] == 't' || Fmt[i] == 'j' || Fmt[i] == 'h')) {
      // consume but we don't use them for now
      // Handle 'hh' quickly
      if ((Fmt[i] == 'h') && (i + 1 < e) && (Fmt[i+1] == 'h'))
        i += 2;
      else
        i += 1;
    }

    if (i >= e) break;
    char conv = Fmt[i];
    // Record every conversion to keep argument index mapping
    ConvMods.emplace_back(hasLL, hasL);
    ConvChars.push_back(conv);
  }
}

bool SAGenTestChecker::argLooksSectorLike(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  // Prefer DeclRefExpr names
  const Expr *EI = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(EI)) {
    if (const auto *ND = DRE->getDecl()) {
      return isSectorLikeName(ND->getName());
    }
  }
  // As fallback, look for sector-like tokens in the argument source text
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &Lang = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, Lang);
  return isSectorLikeName(Text);
}

// ---- Main callbacks ----

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Step A: Identify the destination variable and its declaration
  const MemRegion *DstR;
  const VarDecl *VD;
  std::tie(DstR, VD) = getDestRegionAndDecl(Loc, C);
  if (!VD)
    return;

  // Name filter
  StringRef Name = VD->getName();
  if (!isSectorLikeName(Name))
    return;

  // Type of destination
  QualType DstQT = VD->getType();
  if (!isUnsigned32(DstQT, C.getASTContext()))
    return;

  // Step B: Determine RHS and whether it's 64-bit or from min_t(u64, ...)
  const Expr *RHS = getRHSExprFromStmt(S);
  if (!RHS)
    return;

  bool Needs64 = isInt64OrWider(RHS->getType(), C.getASTContext());
  if (!Needs64 && exprOrStmtMentionsMinTU64(S, C))
    Needs64 = true;

  if (!Needs64)
    return;

  // Step C: Warn on likely truncation
  if (wasAlreadyReported(DstR, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "64-bit sector count stored in 32-bit '";
  Msg += Name;
  Msg += "'; use u64.";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);

  // Add ranges for better highlighting
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    R->addRange(BO->getLHS()->getSourceRange());
    R->addRange(BO->getRHS()->getSourceRange());
  } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    if (DS->isSingleDecl()) {
      if (const auto *VD2 = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        R->addRange(VD2->getSourceRange());
        if (VD2->getInit())
          R->addRange(VD2->getInit()->getSourceRange());
      }
    }
  } else if (RHS) {
    R->addRange(RHS->getSourceRange());
  }

  C.emitReport(std::move(R));
  markReported(DstR, C);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned FmtIndex = 0;
  const StringLiteral *FmtSL = nullptr;
  if (!getPrintfLikeInfo(Call, C, FmtIndex, FmtSL))
    return;

  StringRef Fmt = FmtSL->getString();
  std::vector<std::pair<bool,bool>> ConvMods; // pair<hasLL, hasL>
  std::vector<char> ConvChars;
  parseFormatString(Fmt, C.getASTContext(), ConvMods, ConvChars);

  if (ConvMods.size() != ConvChars.size())
    return;

  // Walk conversions to find integer ones, map to arguments
  unsigned ArgBase = FmtIndex + 1;
  for (size_t i = 0, n = ConvChars.size(), argPos = 0; i < n; ++i, ++argPos) {
    char Conv = ConvChars[i];
    bool HasLL = ConvMods[i].first;
    bool HasL  = ConvMods[i].second;

    unsigned ArgIndex = ArgBase + argPos;
    if (ArgIndex >= Call.getNumArgs())
      break;

    const Expr *ArgE = Call.getArgExpr(ArgIndex);
    if (!ArgE)
      continue;

    if (!isIntegerConvChar(Conv))
      continue; // not an integer specifier, but still consumed an arg

    QualType ArgT = ArgE->getType();
    unsigned ArgW = C.getASTContext().getTypeSize(ArgT);

    // Warn for 64-bit value printed with plain %u/%d/%x (no l/ll)
    if (!HasLL && !HasL && ArgW >= 64) {
      // Guard: either argument looks sector-like or format mentions 'sector'
      bool Related = argLooksSectorLike(ArgE, C) ||
                     Fmt.contains_insensitive("sector");
      if (!Related)
        continue;

      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "64-bit value formatted with %u; use %llu.", N);
      R->addRange(FmtSL->getSourceRange());
      C.emitReport(std::move(R));
      // Do not early return; multiple issues can coexist but it's fine to continue.
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects truncation of 64-bit sector/reservation values into 32-bit and wrong printf formats",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
