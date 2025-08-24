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

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: Track the per-iteration allocation symbol per enclosing loop.
REGISTER_MAP_WITH_PROGRAMSTATE(LoopAllocSymMap, const Stmt*, SymbolRef)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::BranchCondition
     > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Per-iteration resource leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  bool isPerIterAllocator(const CallEvent &Call, CheckerContext &C) const;
  bool isPerIterFree(const CallEvent &Call, CheckerContext &C) const;

  const Stmt *getEnclosingLoopStmt(const Stmt *S, CheckerContext &C) const;

  const GotoStmt *thenBranchHasGotoExit(const IfStmt *IfS) const;
  const CallExpr *thenBranchFirstCallExpr(const IfStmt *IfS) const;

  SymbolRef getExprSymbol(const Expr *E, CheckerContext &C) const;

  void reportLeak(const Stmt *LocStmt, CheckerContext &C) const;
};

// -------------------- Helper Implementations --------------------

bool SAGenTestChecker::isPerIterAllocator(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Match common net_device allocators used per-iteration.
  if (ExprHasName(OriginExpr, "alloc_etherdev", C) ||
      ExprHasName(OriginExpr, "alloc_etherdev_mqs", C) ||
      ExprHasName(OriginExpr, "alloc_netdev", C) ||
      ExprHasName(OriginExpr, "alloc_netdev_mqs", C)) {
    return true;
  }
  return false;
}

bool SAGenTestChecker::isPerIterFree(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, "free_netdev", C);
}

const Stmt *SAGenTestChecker::getEnclosingLoopStmt(const Stmt *S, CheckerContext &C) const {
  if (!S)
    return nullptr;

  if (const ForStmt *FS = findSpecificTypeInParents<ForStmt>(S, C))
    return FS;
  if (const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(S, C))
    return WS;
  if (const DoStmt *DS = findSpecificTypeInParents<DoStmt>(S, C))
    return DS;

  return nullptr;
}

const GotoStmt *SAGenTestChecker::thenBranchHasGotoExit(const IfStmt *IfS) const {
  if (!IfS)
    return nullptr;
  const Stmt *ThenS = IfS->getThen();
  if (!ThenS)
    return nullptr;

  const GotoStmt *GS = findSpecificTypeInChildren<GotoStmt>(ThenS);
  if (!GS)
    return nullptr;

  const LabelDecl *LD = GS->getLabel();
  if (!LD)
    return nullptr;

  if (LD->getName() == "exit")
    return GS;

  return nullptr;
}

const CallExpr *SAGenTestChecker::thenBranchFirstCallExpr(const IfStmt *IfS) const {
  if (!IfS)
    return nullptr;
  const Stmt *ThenS = IfS->getThen();
  if (!ThenS)
    return nullptr;

  return findSpecificTypeInChildren<CallExpr>(ThenS);
}

SymbolRef SAGenTestChecker::getExprSymbol(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  ProgramStateRef State = C.getState();
  SVal V = State->getSVal(E, C.getLocationContext());
  return V.getAsSymbol();
}

void SAGenTestChecker::reportLeak(const Stmt *LocStmt, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible leak: per-iteration net_device not freed on error path", N);
  if (LocStmt)
    R->addRange(LocStmt->getSourceRange());
  C.emitReport(std::move(R));
}

// -------------------- Checker Callbacks --------------------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isPerIterAllocator(Call, C))
    return;

  // Track the allocation symbol for the current loop iteration.
  SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
  if (!RetSym)
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const Stmt *LoopS = getEnclosingLoopStmt(Origin, C);
  if (!LoopS)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<LoopAllocSymMap>(LoopS, RetSym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isPerIterFree(Call, C))
    return;

  // If a free is called on the same symbol we tracked for this loop, clear it.
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  SymbolRef ArgSym = getExprSymbol(Arg0, C);
  if (!ArgSym)
    return;

  ProgramStateRef State = C.getState();

  // Iterate tracked loop allocations and remove any that match the freed symbol.
  auto Map = State->get<LoopAllocSymMap>();
  bool Changed = false;
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    const Stmt *LoopKey = I->first;
    SymbolRef TrackedSym = I->second;
    if (TrackedSym == ArgSym) {
      State = State->remove<LoopAllocSymMap>(LoopKey);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  // Find the surrounding if-statement for this condition.
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  // Only care about early-exit branches inside a loop.
  const Stmt *LoopS = getEnclosingLoopStmt(IfS, C);
  if (!LoopS)
    return;

  // Determine if this is a bail-out branch: goto exit; or return;
  const GotoStmt *GotoExit = thenBranchHasGotoExit(IfS);
  bool HasReturn = false;
  if (!GotoExit) {
    // Check for return in the then-branch
    const Stmt *ThenS = IfS->getThen();
    if (ThenS) {
      const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
      HasReturn = (RS != nullptr);
    }
  }

  if (!GotoExit && !HasReturn)
    return; // Not a bail-out path we care about.

  ProgramStateRef State = C.getState();
  const SymbolRef *TrackedSymPtr = State->get<LoopAllocSymMap>(LoopS);
  if (!TrackedSymPtr)
    return; // No current per-iteration allocation tracked.

  SymbolRef TrackedSym = *TrackedSymPtr;

  // Precision guard: if the first call in the then-branch is free_netdev on this symbol, do not report.
  const CallExpr *FirstCall = thenBranchFirstCallExpr(IfS);
  if (FirstCall) {
    // Use ExprHasName on the call itself to match "free_netdev"
    if (ExprHasName(FirstCall, "free_netdev", C)) {
      if (FirstCall->getNumArgs() >= 1) {
        const Expr *Arg0 = FirstCall->getArg(0);
        if (Arg0) {
          SymbolRef ArgSym = getExprSymbol(Arg0, C);
          if (ArgSym && ArgSym == TrackedSym) {
            // Freed properly before bail-out.
            return;
          }
        }
      }
    }
  }

  // Report potential leak at the bail-out site (goto or condition).
  const Stmt *LocStmt = GotoExit ? static_cast<const Stmt *>(GotoExit)
                                 : static_cast<const Stmt *>(IfS->getCond());
  reportLeak(LocStmt, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects per-iteration resource leaks when bailing out of a loop without freeing the current allocation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
