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
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track currently-held tx_lock regions (base regions)
REGISTER_SET_WITH_PROGRAMSTATE(HeldTxLocks, const MemRegion*)

namespace {

static bool StmtContainsText(const Stmt *S, StringRef Needle, const SourceManager &SM,
                             const LangOptions &LangOpts) {
  if (!S) return false;
  CharSourceRange R = CharSourceRange::getTokenRange(S->getSourceRange());
  StringRef Text = Lexer::getSourceText(R, SM, LangOpts);
  return Text.contains(Needle);
}

static bool StmtContainsText(const Stmt *S, StringRef Needle, CheckerContext &C) {
  return StmtContainsText(S, Needle, C.getSourceManager(), C.getLangOpts());
}

static bool StmtContainsTextAST(const Stmt *S, StringRef Needle, ASTContext &ACtx) {
  return StmtContainsText(S, Needle, ACtx.getSourceManager(), ACtx.getLangOpts());
}

static bool ContainsListAndTxTarget(const Stmt *S, CheckerContext &C) {
  if (!S) return false;
  bool HasList = StmtContainsText(S, "list_for_each_entry_safe", C) ||
                 StmtContainsText(S, "list_for_each_entry", C);
  if (!HasList) return false;
  bool HasTxList = StmtContainsText(S, "tx_ctrl_list", C) ||
                   StmtContainsText(S, "tx_data_list", C);
  return HasList && HasTxList;
}

static bool IsKfreeLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "kfree", C) || ExprHasName(Origin, "kvfree", C);
}

static bool IsSpinLockAcquire(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  // Match spin_lock*, raw_spin_lock*
  return ExprHasName(Origin, "spin_lock", C) || ExprHasName(Origin, "raw_spin_lock", C);
}

static bool IsSpinLockRelease(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  // Match spin_unlock*, raw_spin_unlock*
  return ExprHasName(Origin, "spin_unlock", C) || ExprHasName(Origin, "raw_spin_unlock", C);
}

/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<
    check::PreCall,
    check::ASTCodeBody
  > {
   mutable std::unique_ptr<BugType> BT;

   // Cache: functions that contain tx_* list iterations
   mutable llvm::DenseSet<const FunctionDecl*> FnHasTxListLoop;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unsafe list free without tx_lock", "Concurrency")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      bool inTargetTraversalContext(const Stmt *CallOrigin, CheckerContext &C) const;
      void handleLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      void handleLockRelease(const CallEvent &Call, CheckerContext &C) const;
      void reportUnsafeFree(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::inTargetTraversalContext(const Stmt *CallOrigin, CheckerContext &C) const {
  if (!CallOrigin)
    return false;

  // Check nearest enclosing loops for textual macro tokens
  if (const ForStmt *FS = findSpecificTypeInParents<ForStmt>(CallOrigin, C)) {
    if (ContainsListAndTxTarget(FS, C))
      return true;
  }
  if (const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(CallOrigin, C)) {
    if (ContainsListAndTxTarget(WS, C))
      return true;
  }
  if (const DoStmt *DS = findSpecificTypeInParents<DoStmt>(CallOrigin, C)) {
    if (ContainsListAndTxTarget(DS, C))
      return true;
  }

  // As a fallback, gate by pre-scan result for the enclosing function
  const LocationContext *LCtx = C.getLocationContext();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LCtx ? LCtx->getDecl() : nullptr);
  if (FD && FnHasTxListLoop.count(FD))
    return true;

  return false;
}

void SAGenTestChecker::handleLockAcquire(const CallEvent &Call, CheckerContext &C) const {
  // Only track tx_lock acquisitions
  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  if (!ExprHasName(Arg0, "tx_lock", C))
    return;

  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<HeldTxLocks>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::handleLockRelease(const CallEvent &Call, CheckerContext &C) const {
  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  if (!ExprHasName(Arg0, "tx_lock", C))
    return;

  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = State->remove<HeldTxLocks>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::reportUnsafeFree(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing tx_* list entries without holding tx_lock (possible UAF)", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Track spin lock acquire/release
  if (IsSpinLockAcquire(Call, C)) {
    handleLockAcquire(Call, C);
    return;
  }
  if (IsSpinLockRelease(Call, C)) {
    handleLockRelease(Call, C);
    return;
  }

  // Detect unsafe frees
  if (!IsKfreeLike(Call, C))
    return;

  // Only interested if inside/around tx_* list traversal
  if (!inTargetTraversalContext(Origin, C))
    return;

  ProgramStateRef State = C.getState();
  auto Locks = State->get<HeldTxLocks>();
  if (Locks.isEmpty()) {
    reportUnsafeFree(Call, C);
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &ACtx = Mgr.getASTContext();

  bool HasList = StmtContainsTextAST(Body, "list_for_each_entry_safe", ACtx) ||
                 StmtContainsTextAST(Body, "list_for_each_entry", ACtx);
  bool HasTx = StmtContainsTextAST(Body, "tx_ctrl_list", ACtx) ||
               StmtContainsTextAST(Body, "tx_data_list", ACtx);

  if (HasList && HasTx) {
    FnHasTxListLoop.insert(FD);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing tx_* list entries without holding tx_lock during list traversal (possible UAF)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
