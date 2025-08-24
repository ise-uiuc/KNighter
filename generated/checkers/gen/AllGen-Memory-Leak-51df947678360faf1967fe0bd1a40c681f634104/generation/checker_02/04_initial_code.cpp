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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track current-iteration resource per loop, and completion state.
REGISTER_MAP_WITH_PROGRAMSTATE(LoopCurResMap, const Stmt*, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(CompletedResSet, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::PreCall,
        check::PreStmt<GotoStmt>
      > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Leaked current-iteration resource", "Memory Management")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreStmt(const GotoStmt *GS, CheckerContext &C) const;

   private:
      // Helpers
      static const Stmt *getEnclosingLoop(const Stmt *S, CheckerContext &C);
      static bool isAllocatorCallExpr(const Expr *E, CheckerContext &C);
      static bool isFreeNetdev(const CallEvent &Call, CheckerContext &C);
      static bool isRegisterNetdev(const CallEvent &Call, CheckerContext &C);
      static bool isExitLikeLabel(const GotoStmt *GS);
};

const Stmt *SAGenTestChecker::getEnclosingLoop(const Stmt *S, CheckerContext &C) {
  if (!S) return nullptr;
  if (const auto *FS = findSpecificTypeInParents<ForStmt>(S, C))
    return FS;
  if (const auto *WS = findSpecificTypeInParents<WhileStmt>(S, C))
    return WS;
  if (const auto *DS = findSpecificTypeInParents<DoStmt>(S, C))
    return DS;
  return nullptr;
}

bool SAGenTestChecker::isAllocatorCallExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE) return false;

  // Use source-text name matching as suggested.
  return ExprHasName(CE, "alloc_etherdev", C) ||
         ExprHasName(CE, "alloc_netdev", C) ||
         ExprHasName(CE, "alloc_netdev_mqs", C);
}

bool SAGenTestChecker::isFreeNetdev(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "free_netdev", C);
}

bool SAGenTestChecker::isRegisterNetdev(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "register_netdev", C);
}

bool SAGenTestChecker::isExitLikeLabel(const GotoStmt *GS) {
  if (!GS || !GS->getLabel()) return false;
  StringRef Name = GS->getLabel()->getName();
  std::string Lower = Name.lower();
  return Lower.find("exit") != std::string::npos ||
         Lower.find("err")  != std::string::npos ||
         Lower.find("out")  != std::string::npos ||
         Lower.find("fail") != std::string::npos;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Only consider declaration with initializer or assignment.
  const DeclStmt *DS = dyn_cast<DeclStmt>(S);
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!DS && !BO)
    return;

  // Find a call expression on RHS within this statement.
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE)
    return;

  if (!isAllocatorCallExpr(CE, C))
    return;

  // Find enclosing loop (for per-iteration resource).
  const Stmt *Loop = getEnclosingLoop(S, C);
  if (!Loop)
    return;

  // Destination region (the LHS variable).
  const MemRegion *DestR = Loc.getAsRegion();
  if (!DestR)
    return;
  DestR = DestR->getBaseRegion();
  if (!DestR)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<LoopCurResMap>(Loop, DestR);
  State = State->remove<CompletedResSet>(DestR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const Stmt *Loop = getEnclosingLoop(Origin, C);
  if (!Loop)
    return;

  // free_netdev(ndev)
  if (isFreeNetdev(Call, C)) {
    if (Call.getNumArgs() < 1)
      return;
    const Expr *ArgE = Call.getArgExpr(0);
    const MemRegion *ArgR = getMemRegionFromExpr(ArgE, C);
    if (!ArgR)
      return;
    ArgR = ArgR->getBaseRegion();
    if (!ArgR)
      return;

    const MemRegion *CurR = State->get<LoopCurResMap>(Loop);
    if (CurR && CurR == ArgR) {
      State = State->remove<LoopCurResMap>(Loop);
      State = State->remove<CompletedResSet>(ArgR);
      C.addTransition(State);
    }
    return;
  }

  // register_netdev(ndev) -> consider completed
  if (isRegisterNetdev(Call, C)) {
    if (Call.getNumArgs() < 1)
      return;
    const Expr *ArgE = Call.getArgExpr(0);
    const MemRegion *ArgR = getMemRegionFromExpr(ArgE, C);
    if (!ArgR)
      return;
    ArgR = ArgR->getBaseRegion();
    if (!ArgR)
      return;

    const MemRegion *CurR = State->get<LoopCurResMap>(Loop);
    if (CurR && CurR == ArgR) {
      State = State->add<CompletedResSet>(ArgR);
      State = State->remove<LoopCurResMap>(Loop);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkPreStmt(const GotoStmt *GS, CheckerContext &C) const {
  if (!GS)
    return;

  if (!isExitLikeLabel(GS))
    return;

  const Stmt *Loop = getEnclosingLoop(GS, C);
  if (!Loop)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *CurR = State->get<LoopCurResMap>(Loop);
  if (!CurR)
    return;

  // If already completed, assume common cleanup will handle it.
  if (State->contains<CompletedResSet>(CurR))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Leaked current-iteration resource: free before goto to cleanup", N);
  R->addRange(GS->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks for per-iteration allocations when jumping to a shared cleanup without freeing the current resource",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
