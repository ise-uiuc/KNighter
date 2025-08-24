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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(FreedPtrSet, SymbolRef)
REGISTER_MAP_WITH_PROGRAMSTATE(FreedOriginFn, SymbolRef, const IdentifierInfo*)

namespace {

struct KnownCloseFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 2> Params;
};

static const KnownCloseFunction CloseTable[] = {
    // The 3rd parameter (index 2) is the object possibly getting freed.
    {"mptcp_close_ssk", {2}},
    // Optionally, broaden coverage:
    {"kfree", {0}},
    {"kvfree", {0}},
};

class SAGenTestChecker : public Checker<check::PostCall, check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-free read after close/free", "Memory Error")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      // Helper to recognize known close/free-like calls.
      bool isKnownCloseCall(const CallEvent &Call,
                            CheckerContext &C,
                            llvm::SmallVectorImpl<unsigned> &FreedParams,
                            const IdentifierInfo *&ID,
                            StringRef &MatchedName) const;

      // Extract the base object's symbol from an SVal (tries region->symbol first).
      SymbolRef getPointeeSymbol(const SVal &V) const;

      // Try to get symbol of the object from an expression (using region base).
      SymbolRef getObjectSymbolFromExpr(const Expr *E, CheckerContext &C) const;

      // Given a region (possibly a field/element), find the root symbolic object's SymbolRef.
      SymbolRef getBaseSymbolFromRegion(const MemRegion *R) const;

      void reportUAF(SymbolRef Sym, const Stmt *S, CheckerContext &C) const;
};

bool SAGenTestChecker::isKnownCloseCall(const CallEvent &Call,
                                        CheckerContext &C,
                                        llvm::SmallVectorImpl<unsigned> &FreedParams,
                                        const IdentifierInfo *&ID,
                                        StringRef &MatchedName) const {
  const Expr *Origin = Call.getOriginExpr();
  ID = Call.getCalleeIdentifier();

  for (const auto &Entry : CloseTable) {
    bool NameMatch = false;
    if (Origin && ExprHasName(Origin, Entry.Name, C))
      NameMatch = true;
    else if (ID && ID->getName() == Entry.Name)
      NameMatch = true;

    if (NameMatch) {
      FreedParams.clear();
      FreedParams.append(Entry.Params.begin(), Entry.Params.end());
      MatchedName = Entry.Name;
      return true;
    }
  }
  return false;
}

SymbolRef SAGenTestChecker::getBaseSymbolFromRegion(const MemRegion *R) const {
  if (!R)
    return nullptr;
  R = R->getBaseRegion();
  if (const auto *SR = dyn_cast<SymbolicRegion>(R))
    return SR->getSymbol();
  // Walk super regions in case the root isn't directly symbolic.
  const MemRegion *Cur = R;
  while (Cur) {
    if (const auto *SymR = dyn_cast<SymbolicRegion>(Cur))
      return SymR->getSymbol();
    if (const auto *SubR = dyn_cast<SubRegion>(Cur))
      Cur = SubR->getSuperRegion();
    else
      break;
  }
  return nullptr;
}

SymbolRef SAGenTestChecker::getPointeeSymbol(const SVal &V) const {
  if (const MemRegion *MR = V.getAsRegion()) {
    return getBaseSymbolFromRegion(MR);
  }
  // As a fallback, return symbol if present.
  return V.getAsSymbol();
}

SymbolRef SAGenTestChecker::getObjectSymbolFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return getBaseSymbolFromRegion(MR);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 2> Params;
  const IdentifierInfo *ID = nullptr;
  StringRef MatchedName;
  if (!isKnownCloseCall(Call, C, Params, ID, MatchedName))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : Params) {
    if (Idx >= Call.getNumArgs())
      continue;

    // Prefer extracting from the argument SVal (pointee region/symbol).
    SVal ArgV = Call.getArgSVal(Idx);
    SymbolRef Sym = getPointeeSymbol(ArgV);

    // If still not found, try via the expression.
    if (!Sym) {
      const Expr *ArgE = Call.getArgExpr(Idx);
      Sym = getObjectSymbolFromExpr(ArgE, C);
    }

    if (!Sym)
      continue;

    State = State->add<FreedPtrSet>(Sym);
    if (ID)
      State = State->set<FreedOriginFn>(Sym, ID);
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportUAF(SymbolRef Sym, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  StringRef Msg = "Use-after-free read: object may have been freed earlier.";
  if (Sym) {
    ProgramStateRef State = C.getState();
    if (const IdentifierInfo *const *IDP = State->get<FreedOriginFn>(Sym)) {
      const IdentifierInfo *ID = *IDP;
      if (ID && !ID->getName().empty()) {
        SmallString<128> Buf;
        llvm::raw_svector_ostream OS(Buf);
        OS << "Use-after-free read: object may have been freed by '" << ID->getName() << "' before this access.";
        auto R = std::make_unique<PathSensitiveBugReport>(*BT, OS.str(), N);
        if (S)
          R->addRange(S->getSourceRange());
        C.emitReport(std::move(R));
        return;
      }
    }
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = nullptr;

  // 1) Try to extract from expression kinds we care about.
  if (const auto *ME = dyn_cast_or_null<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      Sym = getObjectSymbolFromExpr(Base, C);
    }
  } else if (const auto *UO = dyn_cast_or_null<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Base = UO->getSubExpr();
      Sym = getObjectSymbolFromExpr(Base, C);
    }
  } else if (const auto *ASE = dyn_cast_or_null<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase();
    Sym = getObjectSymbolFromExpr(Base, C);
  }

  // 2) Fallback: derive from the accessed location's region.
  if (!Sym) {
    if (const MemRegion *R = Loc.getAsRegion()) {
      // For field/element region, climb to base symbolic object.
      Sym = getBaseSymbolFromRegion(R);
    }
  }

  if (!Sym)
    return;

  if (!State->contains<FreedPtrSet>(Sym))
    return;

  reportUAF(Sym, S, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free reads after close/free-like calls (e.g., mptcp_close_ssk)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
