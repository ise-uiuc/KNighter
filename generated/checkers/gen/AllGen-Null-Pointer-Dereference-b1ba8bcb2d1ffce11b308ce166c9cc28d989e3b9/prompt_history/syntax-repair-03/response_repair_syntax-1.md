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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track optional-return symbols and regions holding them.
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalRetSyms, SymbolRef, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrRegions, const MemRegion*, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind,
        check::Location> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
                                     "Optional resource NULL dereference",
                                     "Null Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  bool isOptionalGetter(const CallEvent &Call, CheckerContext &C) const;
  bool maybeNullOnThisPath(const Expr *E, CheckerContext &C) const;
  const MemRegion *getTrackedRegion(const Expr *E, CheckerContext &C) const;

  void reportDeref(const Expr *BaseE, CheckerContext &C, StringRef Msg) const;
};

bool SAGenTestChecker::isOptionalGetter(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  QualType RetTy = Call.getResultType();
  if (RetTy.isNull() || !RetTy->isAnyPointerType())
    return false;

  // Recognize known optional getters (names can be used directly via ExprHasName).
  static const char *Names[] = {
      "devm_gpiod_get_array_optional",
      "gpiod_get_array_optional",
      "devm_gpiod_get_optional",
      "gpiod_get_optional",
      "fwnode_gpiod_get_optional"
  };

  for (const char *N : Names) {
    if (ExprHasName(OE, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::maybeNullOnThisPath(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  ProgramStateRef State = C.getState();
  SVal PtrSV = State->getSVal(E, C.getLocationContext());

  if (!PtrSV.getAs<DefinedOrUnknownSVal>())
    return false; // Non-sensical

  SValBuilder &SVB = C.getSValBuilder();
  // Create a zero value of the expression's type, which corresponds to NULL for pointers.
  SVal NullSV = SVB.makeZeroVal(E->getType());

  SVal EqV = SVB.evalEQ(State, PtrSV, NullSV);
  if (EqV.isUndef())
    return false;

  DefinedOrUnknownSVal EqDUV = EqV.castAs<DefinedOrUnknownSVal>();

  // If "Ptr == NULL" is feasible on this path, return true.
  ProgramStateRef ST = State->assume(EqDUV, true);
  if (ST)
    return true;

  return false;
}

const MemRegion *SAGenTestChecker::getTrackedRegion(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isOptionalGetter(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->set<OptionalRetSyms>(Sym, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  std::optional<loc::MemRegionVal> MRV = Loc.getAs<loc::MemRegionVal>();
  if (!MRV)
    return;

  const MemRegion *DestR = MRV->getRegion();
  if (!DestR)
    return;
  DestR = DestR->getBaseRegion();
  if (!DestR)
    return;

  ProgramStateRef State = C.getState();

  bool ComesFromOptional = false;

  // Case A: RHS is a symbol tagged as an optional getter result.
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (const bool *Found = State->get<OptionalRetSyms>(Sym)) {
      (void)Found;
      ComesFromOptional = true;
    }
  }

  // Case B: RHS is a region already tracked as optional-origin (alias propagation).
  if (!ComesFromOptional) {
    if (const MemRegion *SrcR = Val.getAsRegion()) {
      SrcR = SrcR->getBaseRegion();
      if (SrcR) {
        if (const bool *Tracked = State->get<OptionalPtrRegions>(SrcR)) {
          (void)Tracked;
          ComesFromOptional = true;
        }
      }
    }
  }

  if (ComesFromOptional) {
    State = State->set<OptionalPtrRegions>(DestR, true);
  } else {
    // Overwriting with an unrelated value clears the origin tag.
    State = State->remove<OptionalPtrRegions>(DestR);
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportDeref(const Expr *BaseE, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (BaseE)
    R->addRange(BaseE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Look for dereferences via "->" on a tracked optional pointer.
  if (!S)
    return;

  // Find enclosing MemberExpr using "->".
  const MemberExpr *ME = findSpecificTypeInParents<MemberExpr>(S, C);
  if (!ME) {
    // Sometimes the statement itself is a MemberExpr.
    ME = dyn_cast<MemberExpr>(S);
    if (!ME)
      return;
  }

  if (!ME->isArrow())
    return;

  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return;
  BaseE = BaseE->IgnoreParenCasts();

  const MemRegion *BaseR = getTrackedRegion(BaseE, C);
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Tracked = State->get<OptionalPtrRegions>(BaseR);
  if (!Tracked)
    return;

  // If this optional resource may be NULL on this path, report.
  if (maybeNullOnThisPath(BaseE, C)) {
    reportDeref(BaseE, C, "Possible NULL deref of optional resource");
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *ArgR = getTrackedRegion(ArgE, C);
    if (!ArgR)
      continue;

    if (!State->get<OptionalPtrRegions>(ArgR))
      continue;

    if (maybeNullOnThisPath(ArgE, C)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "NULL optional resource passed to a function that dereferences it", N);
      R->addRange(ArgE->getSourceRange());
      C.emitReport(std::move(R));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereferencing optional resources returned by *_get_optional without NULL checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
