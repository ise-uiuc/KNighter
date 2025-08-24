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
#include "llvm/ADT/ImmutableSet.h"
#include <set>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: set of currently held lock regions
REGISTER_SET_WITH_PROGRAMSTATE(HeldLocks, const MemRegion*)
// Program state: whether this function uses locks (set once we see any lock op)
REGISTER_TRAIT_WITH_PROGRAMSTATE(FunctionUsesLocks, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::BeginFunction,
    check::PostCall,
    check::BranchCondition,
    check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   // Global (per-checker-instance) set of protected pointer fields recorded
   // when seen NULL-checked while a lock is held. Keyed by source text string.
   mutable std::set<std::string> ProtectedPtrFields;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Concurrent pointer update after unlocking", "Concurrency")) {}

      void checkBeginFunction(CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helper utilities
      static std::string getExprText(const Expr *E, CheckerContext &C);
      static const Expr* getLockArgExpr(const CallEvent &Call);
      static bool isLockAcquire(const CallEvent &Call, CheckerContext &C);
      static bool isLockRelease(const CallEvent &Call, CheckerContext &C);

      static bool isNullCheckCondition(const Expr *Cond, const MemberExpr* &OutME, CheckerContext &C);
      static const MemberExpr* lhsMemberExprFromStmt(const Stmt *S);
      static bool rhsIsNull(const Stmt *S, CheckerContext &C);

      static bool anyLockHeld(ProgramStateRef State);
      void reportTOCTOU(const MemberExpr *ME, const Stmt *S, CheckerContext &C) const;
};

//------------------------ Helper Implementations ------------------------

std::string SAGenTestChecker::getExprText(const Expr *E, CheckerContext &C) {
  if (!E) return std::string();
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LO = C.getLangOpts();
  CharSourceRange R = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef SR = Lexer::getSourceText(R, SM, LO);
  return SR.str();
}

const Expr* SAGenTestChecker::getLockArgExpr(const CallEvent &Call) {
  if (Call.getNumArgs() == 0)
    return nullptr;

  const Expr *Arg = Call.getArgExpr(0); // lock argument is first for all lock APIs here
  if (!Arg)
    return nullptr;

  const Expr *E = Arg;
  // If '&lock', get the subexpr to represent the actual lock object
  if (const auto *UO = dyn_cast<UnaryOperator>(E->IgnoreParens())) {
    if (UO->getOpcode() == UO_AddrOf) {
      return UO->getSubExpr();
    }
  }
  return E;
}

static bool calleeNameIs(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr) return false;
  return ExprHasName(cast<Expr>(OriginExpr), Name, C);
}

bool SAGenTestChecker::isLockAcquire(const CallEvent &Call, CheckerContext &C) {
  return calleeNameIs(Call, "spin_lock", C) ||
         calleeNameIs(Call, "spin_lock_bh", C) ||
         calleeNameIs(Call, "spin_lock_irqsave", C) ||
         calleeNameIs(Call, "mutex_lock", C) ||
         calleeNameIs(Call, "mutex_lock_interruptible", C);
}

bool SAGenTestChecker::isLockRelease(const CallEvent &Call, CheckerContext &C) {
  return calleeNameIs(Call, "spin_unlock", C) ||
         calleeNameIs(Call, "spin_unlock_bh", C) ||
         calleeNameIs(Call, "spin_unlock_irqrestore", C) ||
         calleeNameIs(Call, "mutex_unlock", C);
}

bool SAGenTestChecker::isNullCheckCondition(const Expr *Cond, const MemberExpr* &OutME, CheckerContext &C) {
  OutME = nullptr;
  if (!Cond) return false;

  const Expr *E = Cond->IgnoreParenCasts();

  // if (!X->field) or if (X->field)
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      if (!Sub) return false;
      if (const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Sub)) {
        if (ME->getType()->isPointerType()) {
          OutME = ME;
          return true;
        }
      }
    }
  }

  // if (X->field == NULL/0) or if (X->field != NULL/0)
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      auto IsNullConst = [&](const Expr *ExprSide) -> bool {
        if (!ExprSide) return false;
        if (ExprSide->isNullPointerConstant(C.getASTContext(),
                                            Expr::NPC_ValueDependentIsNull))
          return true;
        llvm::APSInt Val;
        if (EvaluateExprToInt(Val, ExprSide, C)) {
          if (Val == 0) return true;
        }
        if (ExprHasName(ExprSide, "NULL", C) || ExprHasName(ExprSide, "nullptr", C))
          return true;
        return false;
      };

      const Expr *PtrExpr = nullptr;

      if (IsNullConst(RHS)) PtrExpr = LHS;
      else if (IsNullConst(LHS)) PtrExpr = RHS;

      if (PtrExpr) {
        if (const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(PtrExpr)) {
          if (ME->getType()->isPointerType()) {
            OutME = ME;
            return true;
          }
        }
      }
    }
  }

  // if (X->field)
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->getType()->isPointerType()) {
      OutME = ME;
      return true;
    }
  }
  if (const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (ME->getType()->isPointerType()) {
      OutME = ME;
      return true;
    }
  }

  return false;
}

const MemberExpr* SAGenTestChecker::lhsMemberExprFromStmt(const Stmt *S) {
  if (!S) return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS();
      if (!LHS) return nullptr;
      if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(LHS))
        return ME;
    }
  }
  // Fallback: find first MemberExpr in the statement
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S))
    return ME;

  return nullptr;
}

bool SAGenTestChecker::rhsIsNull(const Stmt *S, CheckerContext &C) {
  if (!S) return false;
  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return false;

  const Expr *RHS = BO->getRHS();
  if (!RHS) return false;
  RHS = RHS->IgnoreParenCasts();

  if (RHS->isNullPointerConstant(C.getASTContext(),
                                 Expr::NPC_ValueDependentIsNull))
    return true;

  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, RHS, C)) {
    if (Val == 0) return true;
  }

  if (ExprHasName(RHS, "NULL", C) || ExprHasName(RHS, "nullptr", C))
    return true;

  return false;
}

bool SAGenTestChecker::anyLockHeld(ProgramStateRef State) {
  auto Locks = State->get<HeldLocks>();
  return !Locks.isEmpty();
}

void SAGenTestChecker::reportTOCTOU(const MemberExpr *ME, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Write of lock-protected pointer after unlocking; possible race (TOCTOU)", N);

  if (ME)
    R->addRange(ME->getSourceRange());
  if (S)
    R->addRange(S->getSourceRange());

  C.emitReport(std::move(R));
}

//------------------------ Checker Callbacks ------------------------

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Clear "uses locks" flag for this function
  State = State->set<FunctionUsesLocks>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track lock acquisitions
  if (isLockAcquire(Call, C)) {
    const Expr *LockExpr = getLockArgExpr(Call);
    if (LockExpr) {
      const MemRegion *MR = getMemRegionFromExpr(LockExpr, C);
      if (MR) {
        MR = MR->getBaseRegion();
        if (MR) {
          State = State->add<HeldLocks>(MR);
          // Mark that this function uses locks
          State = State->set<FunctionUsesLocks>(true);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // Track lock releases
  if (isLockRelease(Call, C)) {
    const Expr *LockExpr = getLockArgExpr(Call);
    if (LockExpr) {
      const MemRegion *MR = getMemRegionFromExpr(LockExpr, C);
      if (MR) {
        MR = MR->getBaseRegion();
        if (MR) {
          State = State->remove<HeldLocks>(MR);
          // still keep FunctionUsesLocks as true for the function
          C.addTransition(State);
          return;
        }
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (!anyLockHeld(State))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const MemberExpr *ME = nullptr;
  if (!isNullCheckCondition(CondE, ME, C))
    return;

  if (!ME || !ME->getType()->isPointerType())
    return;

  // Record this pointer field as lock-protected
  std::string Key = getExprText(ME, C);
  if (!Key.empty())
    ProtectedPtrFields.insert(Key);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // We only care about stores outside of any lock
  if (anyLockHeld(State))
    return;

  // Only report in functions that use locks (to reduce noise)
  const bool UsesLocks = State->get<FunctionUsesLocks>();
  if (!UsesLocks)
    return;

  // Ensure the statement is an assignment and RHS is NULL
  if (!rhsIsNull(S, C))
    return;

  const MemberExpr *ME = lhsMemberExprFromStmt(S);
  if (!ME)
    return;

  // Only pointer-typed member fields assigned to NULL
  if (!ME->getType()->isPointerType())
    return;

  std::string Key = getExprText(ME, C);
  if (Key.empty())
    return;

  // Has this field been seen NULL-checked while holding a lock?
  if (ProtectedPtrFields.find(Key) == ProtectedPtrFields.end())
    return;

  // Report the possible race: write-after-unlock of a lock-protected pointer
  reportTOCTOU(ME, S, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects writes to lock-protected pointer fields after unlocking (TOCTOU race)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
