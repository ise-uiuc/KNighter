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

using namespace clang;
using namespace ento;
using namespace taint;

// Program state traits / maps
REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocRegion, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocCall, const Stmt*)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::Bind,
        check::BranchCondition,
        check::BeginFunction> {

   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Wrong NULL check after allocation", "API Misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;

private:
  // Helpers
  bool isKernelAllocator(const CallEvent &Call, CheckerContext &C) const;
  const MemRegion *getAssignedLHSRegionForCall(const CallEvent &Call, CheckerContext &C) const;
  const MemRegion *resolveAliasRegion(const MemRegion *R, ProgramStateRef State) const;

  struct NullCheckInfo {
    const Expr *PtrExpr = nullptr;   // The expression being checked against NULL.
    bool IsNullOnThen = false;       // True if the 'then' branch is the NULL path.
  };
  bool extractNullCheckInfo(const Expr *CondE, CheckerContext &C, NullCheckInfo &Out) const;

  void clearPendingAlloc(ProgramStateRef &State) const;
};

// Helper: identify allocator calls we care about using origin expr text match as suggested.
bool SAGenTestChecker::isKernelAllocator(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Check common kernel allocators
  return ExprHasName(Origin, "kzalloc", C) ||
         ExprHasName(Origin, "kmalloc", C) ||
         ExprHasName(Origin, "kcalloc", C) ||
         ExprHasName(Origin, "kmalloc_array", C) ||
         ExprHasName(Origin, "kvzalloc", C) ||
         ExprHasName(Origin, "vzalloc", C) ||
         ExprHasName(Origin, "devm_kzalloc", C) ||
         ExprHasName(Origin, "devm_kcalloc", C);
}

// Helper: From a call expression on the RHS, find the parent assignment and return the LHS region.
const MemRegion *SAGenTestChecker::getAssignedLHSRegionForCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return nullptr;

  // Find the parent BinaryOperator which should be an assignment.
  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(Origin, C);
  if (!BO || !BO->isAssignmentOp())
    return nullptr;

  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(LHS, C);
  if (!MR)
    return nullptr;

  MR = MR->getBaseRegion();
  return MR;
}

const MemRegion *SAGenTestChecker::resolveAliasRegion(const MemRegion *R, ProgramStateRef State) const {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break;
    const MemRegion *Next = State->get<PtrAliasMap>(Cur);
    if (!Next)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur;
}

static bool isNullExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;
  return ExprHasName(E, "NULL", C);
}

bool SAGenTestChecker::extractNullCheckInfo(const Expr *CondE, CheckerContext &C, NullCheckInfo &Out) const {
  if (!CondE)
    return false;

  CondE = CondE->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      Out.PtrExpr = UO->getSubExpr();
      Out.IsNullOnThen = true; // !ptr ==> then-branch is NULL path
      return Out.PtrExpr != nullptr;
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsNull = isNullExpr(LHS, C);
      bool RHSIsNull = isNullExpr(RHS, C);

      if (LHSIsNull && !RHSIsNull) {
        Out.PtrExpr = RHS;
        Out.IsNullOnThen = (Op == BO_EQ); // ptr == NULL => then is null
        return true;
      } else if (RHSIsNull && !LHSIsNull) {
        Out.PtrExpr = LHS;
        Out.IsNullOnThen = (Op == BO_EQ);
        return true;
      }
    }
  }

  // We intentionally do not treat "if (ptr)" as a NULL-check here to keep FP low.
  return false;
}

void SAGenTestChecker::clearPendingAlloc(ProgramStateRef &State) const {
  State = State->remove<LastAllocRegion>();
  State = State->remove<LastAllocCall>();
}

// Record the LHS region that received the allocation result.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isKernelAllocator(Call, C))
    return;

  const MemRegion *LHSReg = getAssignedLHSRegionForCall(Call, C);
  if (!LHSReg)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<LastAllocRegion>(LHSReg->getBaseRegion());
  State = State->set<LastAllocCall>(Call.getOriginExpr());
  C.addTransition(State);
}

// Track simple pointer aliases: LHS-reg -> RHS-reg
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *Dst = Loc.getAsRegion();
  const MemRegion *Src = Val.getAsRegion();
  if (!Dst || !Src)
    return;

  Dst = Dst->getBaseRegion();
  Src = Src->getBaseRegion();
  if (!Dst || !Src)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<PtrAliasMap>(Dst, Src);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If we don't have a pending allocation, nothing to do.
  const MemRegion *Pending = State->get<LastAllocRegion>();
  if (!Pending)
    return;

  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    // Not an expression condition; clear pending to only look at immediate next branch.
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  NullCheckInfo Info;
  bool IsNullCheck = extractNullCheckInfo(CondE, C, Info);
  if (!IsNullCheck) {
    // First branch after allocation is unrelated; clear pending.
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  // Find the surrounding IfStmt to examine the null-path body for an immediate return.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS) {
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  const Stmt *NullBranch = Info.IsNullOnThen ? IS->getThen() : IS->getElse();
  if (!NullBranch) {
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(NullBranch);
  if (!RS) {
    // We only warn when the null path immediately returns (typical error handling).
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  // Determine which region is actually being checked in the condition.
  const MemRegion *CheckedReg = nullptr;
  if (Info.PtrExpr) {
    CheckedReg = getMemRegionFromExpr(Info.PtrExpr, C);
    if (CheckedReg)
      CheckedReg = CheckedReg->getBaseRegion();
  }

  const MemRegion *CanonPending = resolveAliasRegion(Pending, State);
  const MemRegion *CanonChecked = resolveAliasRegion(CheckedReg, State);

  // If we cannot resolve regions confidently, do not warn.
  if (!CanonPending || !CanonChecked) {
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  if (CanonPending == CanonChecked) {
    // Correct: the null check is on the allocated pointer.
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  // Wrong pointer is being NULL-checked after allocation; report a bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) {
    clearPendingAlloc(State);
    C.addTransition(State);
    return;
  }

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "NULL check on wrong pointer after allocation", N);
  R->addRange(Condition->getSourceRange());
  if (const Stmt *AllocS = State->get<LastAllocCall>()) {
    SourceRange SR = AllocS->getSourceRange();
    if (SR.isValid())
      R->addRange(SR);
  }
  C.emitReport(std::move(R));

  // Clear pending expectation after reporting.
  clearPendingAlloc(State);
  C.addTransition(State);
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  clearPendingAlloc(State);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL checks on the wrong pointer immediately after allocation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
