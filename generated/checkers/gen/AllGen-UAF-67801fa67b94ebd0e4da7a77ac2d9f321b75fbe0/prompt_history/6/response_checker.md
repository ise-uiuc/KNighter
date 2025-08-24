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
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states to track published objects and already-warned ones
REGISTER_SET_WITH_PROGRAMSTATE(PublishedObjSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(AlreadyWarnedSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::Bind
  > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Premature ID allocation", "Concurrency")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      static bool isPublishAPI(const CallEvent &Call, CheckerContext &C, unsigned &EntryArgIdx);
      void reportPublishBeforeInit(const Stmt *S, const MemRegion *BaseReg, CheckerContext &C) const;

      static const MemRegion *getBaseFromExpr(const Expr *E, CheckerContext &C);
      static const MemRegion *getBaseFromLocSVal(SVal Loc);
};

/// Determine if this call is to xa_alloc/idr_alloc-family and provide the index
/// of the entry pointer parameter.
bool SAGenTestChecker::isPublishAPI(const CallEvent &Call, CheckerContext &C,
                                    unsigned &EntryArgIdx) {
  EntryArgIdx = UINT_MAX;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  bool IsXA = ExprHasName(Origin, "xa_alloc", C);
  bool IsIDR = ExprHasName(Origin, "idr_alloc", C) ||
               ExprHasName(Origin, "idr_alloc_u32", C) ||
               ExprHasName(Origin, "idr_alloc_range", C);

  if (!IsXA && !IsIDR) {
    // Fallback to identifier check if available
    if (const IdentifierInfo *II = Call.getCalleeIdentifier()) {
      StringRef N = II->getName();
      IsXA = (N == "xa_alloc");
      IsIDR = (N == "idr_alloc" || N == "idr_alloc_u32" || N == "idr_alloc_range");
    }
  }

  if (IsXA) {
    // xa_alloc(xa, id, entry, ...) -> entry at index 2
    if (Call.getNumArgs() > 2) {
      EntryArgIdx = 2;
      return true;
    }
    return false;
  }

  if (IsIDR) {
    // idr_alloc*(idr, ptr, ...) -> ptr at index 1
    if (Call.getNumArgs() > 1) {
      EntryArgIdx = 1;
      return true;
    }
    return false;
  }

  return false;
}

const MemRegion *SAGenTestChecker::getBaseFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

const MemRegion *SAGenTestChecker::getBaseFromLocSVal(SVal Loc) {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

void SAGenTestChecker::reportPublishBeforeInit(const Stmt *S,
                                               const MemRegion *BaseReg,
                                               CheckerContext &C) const {
  if (!BaseReg)
    return;

  ProgramStateRef State = C.getState();
  // Avoid duplicate reports on the same path for the same base region
  if (State->contains<AlreadyWarnedSet>(BaseReg))
    return;

  State = State->add<AlreadyWarnedSet>(BaseReg);

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "ID allocated before finishing init; move xa_alloc/idr_alloc to the end", N);

  if (S)
    R->addRange(S->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  unsigned ArgIdx = UINT_MAX;
  if (!isPublishAPI(Call, C, ArgIdx))
    return;

  if (ArgIdx >= Call.getNumArgs())
    return;

  const Expr *ArgE = Call.getArgExpr(ArgIdx);
  const MemRegion *BaseReg = getBaseFromExpr(ArgE, C);
  if (!BaseReg)
    return;

  // Record that this object's pointer has been published into a global ID store
  State = State->add<PublishedObjSet>(BaseReg);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Optionally detect post-publish writes hidden behind helper calls that
  // dereference fields.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    const MemRegion *BaseReg = getBaseFromExpr(ArgE, C);
    if (!BaseReg)
      continue;

    if (State->contains<PublishedObjSet>(BaseReg) &&
        !State->contains<AlreadyWarnedSet>(BaseReg)) {
      reportPublishBeforeInit(Call.getOriginExpr(), BaseReg, C);
      // State transition is done inside report (adds AlreadyWarnedSet).
      return;
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  // Triggered on stores like q->field = ...
  const MemRegion *BaseReg = getBaseFromLocSVal(Loc);
  if (!BaseReg)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<PublishedObjSet>(BaseReg))
    return;

  if (State->contains<AlreadyWarnedSet>(BaseReg))
    return;

  reportPublishBeforeInit(S, BaseReg, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing objects via xa_alloc/idr_alloc before finishing initialization",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
