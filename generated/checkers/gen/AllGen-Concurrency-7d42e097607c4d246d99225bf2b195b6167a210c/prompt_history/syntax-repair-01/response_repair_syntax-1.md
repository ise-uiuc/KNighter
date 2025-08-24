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
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(CompUseMap, const MemRegion*, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(CompLastUseStmt, const MemRegion*, const Stmt*)

namespace {

class SAGenTestChecker : public Checker< check::PostCall, check::EndFunction > {
   mutable std::unique_ptr<BugType> BT;

   // Heuristic TU-wide gate: set true if we ever see wait_for_completion_timeout
   mutable bool SawTimedWaitInTU = false;

   // Flags for CompUseMap
   static constexpr unsigned SEEN_COMPLETE = 0x1;  // complete(&ctx->compl)
   static constexpr unsigned SEEN_KFREE    = 0x2;  // kfree(ctx)
   static constexpr unsigned SEEN_DONE     = 0x4;  // completion_done(&ctx->compl)

   public:
      SAGenTestChecker() : BT(new BugType(this, "Workqueue timed-wait UAF risk", "Concurrency")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:
      // Helpers
      bool callIs(const CallEvent &Call, StringRef Name, CheckerContext &C) const;
      bool isWorkerFunction(const FunctionDecl *FD) const;

      ProgramStateRef setFlag(ProgramStateRef State, const MemRegion *B, unsigned Flag) const;
      ProgramStateRef setLastUse(ProgramStateRef State, const MemRegion *B, const Stmt *S) const;

      const MemRegion *getContextBaseFromCompletionArg(const Expr *ArgE, CheckerContext &C) const;
      const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      void reportMissingGuard(const MemRegion *B, const Stmt *S, CheckerContext &C) const;
};

// Determine if Call refers to a function with given name using source text.
bool SAGenTestChecker::callIs(const CallEvent &Call, StringRef Name, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

// Identify worker function by parameter of type 'struct work_struct *'
bool SAGenTestChecker::isWorkerFunction(const FunctionDecl *FD) const {
  if (!FD)
    return false;

  for (const ParmVarDecl *P : FD->parameters()) {
    QualType QT = P->getType();
    if (!QT->isPointerType())
      continue;
    QualType Pointee = QT->getPointeeType();
    if (const RecordType *RT = Pointee->getAs<RecordType>()) {
      const RecordDecl *RD = RT->getDecl();
      IdentifierInfo *II = RD->getIdentifier();
      if (II && II->getName() == "work_struct")
        return true;
    }
  }
  return false;
}

// Update flag bitmask for a given base region
ProgramStateRef SAGenTestChecker::setFlag(ProgramStateRef State, const MemRegion *B, unsigned Flag) const {
  if (!B)
    return State;
  const unsigned *Old = State->get<CompUseMap>(B);
  unsigned NewFlags = (Old ? *Old : 0) | Flag;
  State = State->set<CompUseMap>(B, NewFlags);
  return State;
}

// Record the last interesting statement for a region
ProgramStateRef SAGenTestChecker::setLastUse(ProgramStateRef State, const MemRegion *B, const Stmt *S) const {
  if (!B || !S)
    return State;
  State = State->set<CompLastUseStmt>(B, S);
  return State;
}

// Get base region for a pointer expression
const MemRegion *SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

// Extract the context base region from an argument expected to be &ctx->compl or a pointer to a completion field.
// Strategy: get region for the arg; if it's a FieldRegion, use its super; otherwise use base.
const MemRegion *SAGenTestChecker::getContextBaseFromCompletionArg(const Expr *ArgE, CheckerContext &C) const {
  if (!ArgE)
    return nullptr;

  ProgramStateRef State = C.getState();
  SVal V = State->getSVal(ArgE, C.getLocationContext());
  const MemRegion *MR = V.getAsRegion();
  if (!MR) {
    MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      return nullptr;
  }

  MR = MR->getBaseRegion();
  // If this is a field region (e.g., &ctx->compl), climb to its super region.
  if (const FieldRegion *FR = dyn_cast<FieldRegion>(MR)) {
    const MemRegion *Super = FR->getSuperRegion();
    if (Super)
      return Super->getBaseRegion();
  }
  // Otherwise return the base region as best-effort.
  return MR ? MR->getBaseRegion() : nullptr;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Heuristic gate: remember if TU uses wait_for_completion_timeout
  if (callIs(Call, "wait_for_completion_timeout", C)) {
    SawTimedWaitInTU = true;
    // No per-region state needed here.
    return;
  }

  // Track complete(&ctx->compl)
  if (callIs(Call, "complete", C)) {
    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *B = getContextBaseFromCompletionArg(Arg0, C);
    if (B) {
      State = setFlag(State, B, SEEN_COMPLETE);
      State = setLastUse(State, B, Call.getOriginExpr());
      C.addTransition(State);
    }
    return;
  }

  // Track completion_done(&ctx->compl)
  if (callIs(Call, "completion_done", C)) {
    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *B = getContextBaseFromCompletionArg(Arg0, C);
    if (B) {
      State = setFlag(State, B, SEEN_DONE);
      C.addTransition(State);
    }
    return;
  }

  // Track kfree(ctx)
  if (callIs(Call, "kfree", C)) {
    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *B = getBaseRegionFromExpr(Arg0, C);
    if (B) {
      State = setFlag(State, B, SEEN_KFREE);
      State = setLastUse(State, B, Call.getOriginExpr());
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::reportMissingGuard(const MemRegion *B, const Stmt *S, CheckerContext &C) const {
  if (!BT)
    return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing completion_done() guard in worker; submitter with timed wait may free the context", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LCtx ? LCtx->getDecl() : nullptr);
  if (!FD)
    return;

  // Focus on worker functions
  if (!isWorkerFunction(FD))
    return;

  // Heuristic: only warn if the TU uses a timed wait
  if (!SawTimedWaitInTU)
    return;

  ProgramStateRef State = C.getState();

  bool Reported = false;
  CompUseMapTy Map = State->get<CompUseMap>();
  for (CompUseMapTy::iterator I = Map.begin(), E = Map.end(); I != E; ++I) {
    const MemRegion *B = I->first;
    unsigned Flags = I->second;

    if ((Flags & (SEEN_COMPLETE | SEEN_KFREE)) != 0 && (Flags & SEEN_DONE) == 0) {
      const Stmt *const *LastPtr = State->get<CompLastUseStmt>(B);
      const Stmt *Last = LastPtr ? *LastPtr : nullptr;
      reportMissingGuard(B, Last, C);
      Reported = true;
    }
  }

  // If we reported, we are done. No need to mutate state here for now.
  (void)Reported;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing completion_done() guard in workqueue worker that may race with submitter timeout and free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
