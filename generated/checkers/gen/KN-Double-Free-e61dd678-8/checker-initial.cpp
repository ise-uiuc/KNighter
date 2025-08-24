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
#include "llvm/ADT/ImmutableSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include <string>
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

using TokenSet = llvm::ImmutableSet<const IdentifierInfo *>;
REGISTER_MAP_WITH_PROGRAMSTATE(ExplicitFreedTokensMap, const MemRegion*, TokenSet)
REGISTER_MAP_WITH_PROGRAMSTATE(HelperFreedTokensMap,  const MemRegion*, TokenSet)

namespace {
class SAGenTestChecker : public Checker<check::PreCall, check::BeginFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free of struct member", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBeginFunction(CheckerContext &C) const;

   private:
      // Recognizers
      bool callNameIs(const CallEvent &Call, CheckerContext &C, StringRef Name) const;
      bool isDeallocatorCall(const CallEvent &Call, CheckerContext &C) const;
      bool isHelperFree(const CallEvent &Call, CheckerContext &C, StringRef &OutName) const;

      // Token helpers
      static bool isGenericFreeWord(StringRef Tok);
      static std::string primaryPrefixToken(StringRef FieldName);
      void collectHelperTokens(StringRef CalleeName,
                               SmallVectorImpl<const IdentifierInfo*> &Out,
                               ASTContext &ACtx) const;

      ProgramStateRef addTokensToMap(ProgramStateRef State, bool IsExplicit,
                                     const MemRegion *BaseReg,
                                     ArrayRef<const IdentifierInfo*> Tokens) const;

      const TokenSet *getTokensFromMap(ProgramStateRef State, bool IsExplicit,
                                       const MemRegion *BaseReg) const;

      bool anyTokenInSet(const TokenSet *SetPtr,
                         ArrayRef<const IdentifierInfo*> Tokens) const;

      void reportDoubleFree(const Stmt *Anchor, StringRef HelperName,
                            CheckerContext &C) const;
};

// -------- Utility implementations --------

bool SAGenTestChecker::callNameIs(const CallEvent &Call, CheckerContext &C, StringRef Name) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;
  return ExprHasName(OE, Name, C);
}

bool SAGenTestChecker::isDeallocatorCall(const CallEvent &Call, CheckerContext &C) const {
  // Use ExprHasName to verify known deallocators
  return callNameIs(Call, C, "kfree") || callNameIs(Call, C, "kvfree") || callNameIs(Call, C, "vfree");
}

bool SAGenTestChecker::isHelperFree(const CallEvent &Call, CheckerContext &C, StringRef &OutName) const {
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID)
    return false;

  StringRef Name = ID->getName();
  OutName = Name;

  // Must contain "free" to be considered a free-like helper,
  // but exclude the raw deallocators we treat separately.
  if (!Name.contains_lower("free"))
    return false;

  if (Name.equals("kfree") || Name.equals("kvfree") || Name.equals("vfree"))
    return false;

  return true;
}

bool SAGenTestChecker::isGenericFreeWord(StringRef Tok) {
  // Ignore generic free-related words
  static const char *Ignored[] = {
    "free","put","del","exit","destroy","cleanup","release","uninit","remove"
  };
  for (const char *I : Ignored)
    if (Tok.equals_lower(I))
      return true;
  return false;
}

std::string SAGenTestChecker::primaryPrefixToken(StringRef FieldName) {
  // Return substring before first '_' if present, else the whole name
  std::pair<StringRef, StringRef> P = FieldName.split('_');
  return P.first.str();
}

void SAGenTestChecker::collectHelperTokens(StringRef CalleeName,
                                           SmallVectorImpl<const IdentifierInfo*> &Out,
                                           ASTContext &ACtx) const {
  SmallVector<StringRef, 8> Parts;
  CalleeName.split(Parts, '_');
  for (StringRef P : Parts) {
    if (P.empty()) continue;
    if (isGenericFreeWord(P)) continue;
    const IdentifierInfo &II = ACtx.Idents.get(P);
    Out.push_back(&II);
  }
}

ProgramStateRef SAGenTestChecker::addTokensToMap(ProgramStateRef State, bool IsExplicit,
                                                 const MemRegion *BaseReg,
                                                 ArrayRef<const IdentifierInfo*> Tokens) const {
  if (!BaseReg)
    return State;

  BaseReg = BaseReg->getBaseRegion();
  if (!BaseReg)
    return State;

  TokenSet::Factory &F = State->get_context<TokenSet>();
  const TokenSet *Existing = IsExplicit
                             ? State->get<ExplicitFreedTokensMap>(BaseReg)
                             : State->get<HelperFreedTokensMap>(BaseReg);
  TokenSet S = Existing ? *Existing : F.getEmptySet();

  for (const IdentifierInfo *II : Tokens) {
    S = F.add(II, S);
  }

  if (IsExplicit)
    State = State->set<ExplicitFreedTokensMap>(BaseReg, S);
  else
    State = State->set<HelperFreedTokensMap>(BaseReg, S);

  return State;
}

const TokenSet *SAGenTestChecker::getTokensFromMap(ProgramStateRef State, bool IsExplicit,
                                                   const MemRegion *BaseReg) const {
  if (!BaseReg)
    return nullptr;
  BaseReg = BaseReg->getBaseRegion();
  if (!BaseReg)
    return nullptr;
  return IsExplicit ? State->get<ExplicitFreedTokensMap>(BaseReg)
                    : State->get<HelperFreedTokensMap>(BaseReg);
}

bool SAGenTestChecker::anyTokenInSet(const TokenSet *SetPtr,
                                     ArrayRef<const IdentifierInfo*> Tokens) const {
  if (!SetPtr)
    return false;
  const TokenSet &S = *SetPtr;
  for (const IdentifierInfo *II : Tokens)
    if (S.contains(II))
      return true;
  return false;
}

void SAGenTestChecker::reportDoubleFree(const Stmt *Anchor, StringRef HelperName,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg = "Double free of struct member via kfree() and helper";
  if (!HelperName.empty()) {
    Msg += " '";
    Msg += HelperName.str();
    Msg += "'";
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (Anchor)
    R->addRange(Anchor->getSourceRange());
  C.emitReport(std::move(R));
}

// -------- Checker callbacks --------

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  // Per-function tracking is naturally path-local; no explicit clearing required.
  // Still, ensure a transition exists for the engine.
  C.addTransition(C.getState());
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  ASTContext &ACtx = C.getASTContext();

  // Case A: Explicit deallocation like kfree/kvfree/vfree of a struct member.
  if (isDeallocatorCall(Call, C)) {
    if (Call.getNumArgs() == 0) {
      C.addTransition(State);
      return;
    }

    const Expr *Arg0E = Call.getArgExpr(0);
    if (!Arg0E) {
      C.addTransition(State);
      return;
    }

    // We only consider kfree of a MemberExpr (struct member), as per plan.
    const MemberExpr *ME = dyn_cast<MemberExpr>(Arg0E->IgnoreParenCasts());
    if (!ME) {
      C.addTransition(State);
      return;
    }

    const ValueDecl *VD = ME->getMemberDecl();
    const FieldDecl *FD = dyn_cast_or_null<FieldDecl>(VD);
    if (!FD) {
      C.addTransition(State);
      return;
    }

    // Base object region (e.g., 'ca' in ca->field)
    const MemRegion *BaseReg = getMemRegionFromExpr(ME->getBase(), C);
    if (!BaseReg) {
      C.addTransition(State);
      return;
    }
    BaseReg = BaseReg->getBaseRegion();
    if (!BaseReg) {
      C.addTransition(State);
      return;
    }

    // Tokens: full field name and primary prefix
    StringRef FullName = FD->getName();
    std::string Prefix = primaryPrefixToken(FullName);

    SmallVector<const IdentifierInfo*, 4> FieldTokens;
    const IdentifierInfo &II_Full   = ACtx.Idents.get(FullName);
    FieldTokens.push_back(&II_Full);

    const IdentifierInfo &II_Prefix = ACtx.Idents.get(Prefix);
    FieldTokens.push_back(&II_Prefix);

    // Update explicit-free tokens for this base object
    State = addTokensToMap(State, /*IsExplicit=*/true, BaseReg, FieldTokens);

    // If helper-free tokens already include these, report
    const TokenSet *HelperSet = getTokensFromMap(State, /*IsExplicit=*/false, BaseReg);
    if (anyTokenInSet(HelperSet, FieldTokens)) {
      reportDoubleFree(Arg0E, StringRef(), C);
      C.addTransition(State);
      return;
    }

    C.addTransition(State);
    return;
  }

  // Case B: Helper free calls whose names contain "free" (not the raw deallocators)
  StringRef HelperName;
  if (isHelperFree(Call, C, HelperName)) {
    // Collect tokens from the helper function name (excluding generic words)
    SmallVector<const IdentifierInfo*, 8> HelperTokens;
    collectHelperTokens(HelperName, HelperTokens, ACtx);

    bool Reported = false;
    // For each argument, map tokens to the base object region and check intersection
    for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
      const Expr *ArgE = Call.getArgExpr(I);
      if (!ArgE) continue;

      const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
      if (!MR) continue;
      MR = MR->getBaseRegion();
      if (!MR) continue;

      // Update helper-free tokens for this base region
      State = addTokensToMap(State, /*IsExplicit=*/false, MR, HelperTokens);

      // Compare with explicit-free tokens for the same base
      const TokenSet *ExplicitSet = getTokensFromMap(State, /*IsExplicit=*/true, MR);
      if (anyTokenInSet(ExplicitSet, HelperTokens)) {
        reportDoubleFree(Call.getOriginExpr(), HelperName, C);
        Reported = true;
        // Continue processing to keep state consistent; but we already reported.
      }
    }

    C.addTransition(State);
    return;
  }

  // Default path
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of a struct member freed both via kfree() and a helper function",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
