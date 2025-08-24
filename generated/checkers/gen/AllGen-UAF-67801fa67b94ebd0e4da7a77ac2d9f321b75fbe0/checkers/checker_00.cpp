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

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(PendingPublishMap, SymbolRef, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(PublishedObjMap, const MemRegion*, bool)

namespace {
class SAGenTestChecker
  : public Checker<
      check::PostCall,
      eval::Assume,
      check::Location,
      check::PreCall
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "ID publication before finishing initialization", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      static bool isPublishCall(const CallEvent &Call, unsigned &ObjArgIdx, CheckerContext &C);
      static const MemRegion *getPointeeBaseRegionFromSVal(SVal V);
      void reportUseAfterPublish(const Stmt *S, CheckerContext &C) const;
      void reportUseAfterPublishForCall(const CallEvent &Call, unsigned ArgIdx, CheckerContext &C) const;
};

bool SAGenTestChecker::isPublishCall(const CallEvent &Call, unsigned &ObjArgIdx, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Use ExprHasName for robust name matching
  if (ExprHasName(OriginExpr, "xa_alloc", C)) {
    ObjArgIdx = 2; // xa_alloc(..., &id, obj, ...)
    return Call.getNumArgs() > ObjArgIdx;
  }
  if (ExprHasName(OriginExpr, "idr_alloc", C)) {
    ObjArgIdx = 1; // idr_alloc(idr, obj, start, end)
    return Call.getNumArgs() > ObjArgIdx;
  }
  if (ExprHasName(OriginExpr, "idr_alloc_u32", C)) {
    ObjArgIdx = 1; // idr_alloc_u32(idr, obj, &id, gfp)
    return Call.getNumArgs() > ObjArgIdx;
  }
  return false;
}

const MemRegion *SAGenTestChecker::getPointeeBaseRegionFromSVal(SVal V) {
  const MemRegion *MR = V.getAsRegion();
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned ObjIdx = 0;
  if (!isPublishCall(Call, ObjIdx, C))
    return;

  ProgramStateRef State = C.getState();

  // Extract the object pointee's base region.
  const MemRegion *ObjRegion = getPointeeBaseRegionFromSVal(Call.getArgSVal(ObjIdx));
  if (!ObjRegion)
    return;

  // Track the return symbol to disambiguate success via evalAssume.
  SVal RetSVal = Call.getReturnValue();
  SymbolRef RetSym = RetSVal.getAsSymbol();

  if (RetSym) {
    // Pending publish until we know the success path (err == 0)
    State = State->set<PendingPublishMap>(RetSym, ObjRegion);
  } else {
    // Fallback: if return is not symbolic, conservatively consider published
    State = State->set<PublishedObjMap>(ObjRegion, true);
  }

  C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  // We only care about conditions looking like "if (err)" immediately after a publish call.
  SymbolRef CondSym = Cond.getAsSymbol();
  if (!CondSym)
    return State;

  const MemRegion *const *ObjRegionPtr = State->get<PendingPublishMap>(CondSym);
  if (!ObjRegionPtr)
    return State;
  const MemRegion *ObjRegion = *ObjRegionPtr;

  // For "if (err)" - false branch (Assumption == false) means err == 0 => success.
  if (!Assumption) {
    State = State->set<PublishedObjMap>(ObjRegion, true);
  }

  // Remove from pending regardless of the branch, we consumed it.
  State = State->remove<PendingPublishMap>(CondSym);
  return State;
}

void SAGenTestChecker::reportUseAfterPublish(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Object used after publishing ID; make ID allocation the last step", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportUseAfterPublishForCall(const CallEvent &Call, unsigned ArgIdx, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Passing object to a dereferencing function after ID publication", N);
  if (const Expr *E = Call.getArgExpr(ArgIdx))
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  // Always use base region
  const MemRegion *Base = MR->getBaseRegion();
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  const bool *IsPublished = State->get<PublishedObjMap>(Base);
  if (IsPublished && *IsPublished) {
    // Any load/store through the object after publication is suspicious.
    reportUseAfterPublish(S, C);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Ignore the publishing calls themselves here.
  unsigned Dummy;
  if (isPublishCall(Call, Dummy, C))
    return;

  // If the callee is known to dereference some pointer parameters, and we pass
  // a published object for those, report.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const MemRegion *ArgReg = getPointeeBaseRegionFromSVal(Call.getArgSVal(Idx));
    if (!ArgReg)
      continue;

    const bool *IsPublished = State->get<PublishedObjMap>(ArgReg);
    if (IsPublished && *IsPublished) {
      reportUseAfterPublishForCall(Call, Idx, C);
      // Don't break; continue to find all problematic args if any.
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects using an object after publishing it to an ID table (xa_alloc/idr_alloc) before finishing initialization",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
