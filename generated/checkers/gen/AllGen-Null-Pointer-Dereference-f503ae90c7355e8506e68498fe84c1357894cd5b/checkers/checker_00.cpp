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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track symbols that are possibly-NULL pointers returned by the capability helper
REGISTER_SET_WITH_PROGRAMSTATE(UncheckedCapPtrSyms, SymbolRef)

namespace {

class SAGenTestChecker : public Checker<
                           check::PostCall,
                           check::Bind,
                           check::Location> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Dereference of capability pointer without NULL check",
                       "API Misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  bool isCapHelper(const CallEvent &Call, CheckerContext &C) const;

  // Walk up the region chain to find the base Symbol. Set WentThroughSubRegion
  // to true if we traversed any SubRegion (i.e., a dereference-like access).
  SymbolRef tryGetBaseSymbolFromRegionChain(const MemRegion *R,
                                            bool &WentThroughSubRegion) const;

  bool isDefinitelyNonNull(SymbolRef Sym, ProgramStateRef State,
                           CheckerContext &C) const;

  bool shouldReport(SymbolRef Sym, bool WentThroughSubRegion,
                    ProgramStateRef State, CheckerContext &C) const;

  void reportDereference(const Stmt *S, CheckerContext &C) const;
};

bool SAGenTestChecker::isCapHelper(const CallEvent &Call,
                                   CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "mt76_connac_get_he_phy_cap", C);
}

SymbolRef SAGenTestChecker::tryGetBaseSymbolFromRegionChain(
    const MemRegion *R, bool &WentThroughSubRegion) const {
  WentThroughSubRegion = false;
  const MemRegion *Cur = R;
  while (Cur) {
    if (const auto *SymR = dyn_cast<SymbolicRegion>(Cur)) {
      return SymR->getSymbol();
    }
    if (const auto *SubR = dyn_cast<SubRegion>(Cur)) {
      WentThroughSubRegion = true;
      Cur = SubR->getSuperRegion();
      continue;
    }
    break;
  }
  return nullptr;
}

bool SAGenTestChecker::isDefinitelyNonNull(SymbolRef Sym,
                                           ProgramStateRef State,
                                           CheckerContext &C) const {
  if (!Sym || !State)
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  SVal PtrVal = SVB.makeLoc(Sym);
  if (!PtrVal.getAs<Loc>())
    return false;

  // Assume on the pointer's truthiness: true -> non-null, false -> null.
  DefinedOrUnknownSVal Cond = PtrVal.castAs<DefinedOrUnknownSVal>();
  ProgramStateRef StIfNonNull = State->assume(Cond, true);
  ProgramStateRef StIfNull = State->assume(Cond, false);

  // Definitely non-null if null is impossible and non-null is possible.
  return (StIfNonNull != nullptr) && (StIfNull == nullptr);
}

bool SAGenTestChecker::shouldReport(SymbolRef Sym, bool WentThroughSubRegion,
                                    ProgramStateRef State,
                                    CheckerContext &C) const {
  if (!Sym || !WentThroughSubRegion || !State)
    return false;

  // Only consider symbols known to originate from the capability helper.
  if (!State->contains<UncheckedCapPtrSyms>(Sym))
    return false;

  // Do not report if the pointer is proven non-null on this path.
  if (isDefinitelyNonNull(Sym, State, C))
    return false;

  return true;
}

void SAGenTestChecker::reportDereference(const Stmt *S,
                                         CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Dereference of pointer returned by mt76_connac_get_he_phy_cap without NULL check", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isCapHelper(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  State = State->add<UncheckedCapPtrSyms>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal /*Loc*/, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  // We are interested in values that are locations derived from regions,
  // e.g., &vc->field or vc[0], which implies dereferencing 'vc'.
  const MemRegion *R = Val.getAsRegion();
  if (!R)
    return;

  bool Through = false;
  SymbolRef BaseSym = tryGetBaseSymbolFromRegionChain(R, Through);
  if (!BaseSym)
    return;

  if (shouldReport(BaseSym, Through, C.getState(), C))
    reportDereference(S, C);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool /*IsLoad*/, const Stmt *S,
                                     CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  bool Through = false;
  SymbolRef BaseSym = tryGetBaseSymbolFromRegionChain(R, Through);
  if (!BaseSym)
    return;

  if (shouldReport(BaseSym, Through, C.getState(), C))
    reportDereference(S, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of pointers returned by mt76_connac_get_he_phy_cap without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
