#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: Remember the lvalue region that received the latest allocation result
REGISTER_TRAIT_WITH_PROGRAMSTATE(PendingAllocRegion, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::BranchCondition,
        check::BeginFunction,
        check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Mismatched NULL check after allocation",
                       "Logic error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helpers
  static bool isAllocator(const CallEvent &Call, CheckerContext &C);
  const MemRegion *getAssignedLHSRegionForCall(const CallEvent &Call,
                                               CheckerContext &C) const;

  static bool isNullCheck(const Expr *Cond, const Expr *&CheckedExpr,
                          CheckerContext &C);
  static bool sameRegion(const MemRegion *A, const MemRegion *B) {
    if (!A || !B)
      return false;
    A = A->getBaseRegion();
    B = B->getBaseRegion();
    return A == B;
  }

  void reportMismatch(const Stmt *Condition, CheckerContext &C) const;
};

// Determine if the call is to a known allocator.
bool SAGenTestChecker::isAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Use the provided ExprHasName helper for robust name checks.
  static const char *Names[] = {
      "kzalloc", "kmalloc", "kcalloc", "kmalloc_array",
      "devm_kzalloc", "vmalloc", "kvzalloc", "kmemdup"};
  for (const char *N : Names) {
    if (ExprHasName(OriginExpr, N, C))
      return true;
  }
  return false;
}

// Find the lvalue region to which the allocation result is assigned.
// Handles patterns:
//   - X = alloc(...);
//   - type X = alloc(...);
const MemRegion *SAGENTestChecker_getRegionFromVarDecl(const VarDecl *VD,
                                                       CheckerContext &C) {
  if (!VD)
    return nullptr;
  const LocationContext *LCtx = C.getLocationContext();
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const VarRegion *VR = MRMgr.getVarRegion(VD, LCtx);
  if (!VR)
    return nullptr;
  return VR->getBaseRegion();
}

const MemRegion *
SAGenTestChecker::getAssignedLHSRegionForCall(const CallEvent &Call,
                                              CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return nullptr;

  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE)
    return nullptr;

  // First, try to find an assignment 'LHS = <this call>'
  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(CE, C)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS();
      if (!RHS)
        return nullptr;
      const Expr *RHSNoC = RHS->IgnoreParenImpCasts();
      const Expr *CENoC = CE->IgnoreParenImpCasts();
      if (RHSNoC == CENoC) {
        const Expr *LHS = BO->getLHS();
        if (!LHS)
          return nullptr;
        const MemRegion *MR = getMemRegionFromExpr(LHS, C);
        if (!MR)
          return nullptr;
        return MR->getBaseRegion();
      }
    }
  }

  // Next, try a variable declaration with initializer 'type X = <this call>'
  if (const auto *DS = findSpecificTypeInParents<DeclStmt>(CE, C)) {
    const Expr *CENoC = CE->IgnoreParenImpCasts();
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (const Expr *Init = VD->getInit()) {
          const Expr *InitNoC = Init->IgnoreParenImpCasts();
          if (InitNoC == CENoC) {
            return SAGENTestChecker_getRegionFromVarDecl(VD, C);
          }
        }
      }
    }
  }

  return nullptr;
}

// Identify explicit NULL checks and extract the checked expression.
// Recognizes: !ptr, ptr == NULL/0, ptr != NULL/0.
// Does NOT treat "if (ptr)" as a NULL-check for this pattern.
bool SAGenTestChecker::isNullCheck(const Expr *Cond, const Expr *&CheckedExpr,
                                   CheckerContext &C) {
  if (!Cond)
    return false;

  ASTContext &ACtx = C.getASTContext();
  const Expr *E = Cond->IgnoreParenCasts();

  // !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      if (!Sub)
        return false;
      CheckedExpr = Sub->IgnoreParenImpCasts();
      return true;
    }
    return false;
  }

  // ptr == NULL/0 or ptr != NULL/0
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      if (!LHS || !RHS)
        return false;

      auto IsNullLike = [&](const Expr *X) -> bool {
        return X->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull) ||
               ExprHasName(X, "NULL", C);
      };

      const Expr *LHSNoC = LHS->IgnoreParenImpCasts();
      const Expr *RHSNoC = RHS->IgnoreParenImpCasts();

      bool LHSIsNull = IsNullLike(LHSNoC);
      bool RHSIsNull = IsNullLike(RHSNoC);

      if (LHSIsNull && !RHSIsNull) {
        CheckedExpr = RHSNoC;
        return true;
      }
      if (RHSIsNull && !LHSIsNull) {
        CheckedExpr = LHSNoC;
        return true;
      }
      return false;
    }
    return false;
  }

  // Do not treat other truthiness checks as NULL-checks.
  return false;
}

void SAGenTestChecker::reportMismatch(const Stmt *Condition,
                                      CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Mismatched NULL check: checks a different pointer than the newly "
           "allocated one",
      N);
  if (Condition)
    R->addRange(Condition->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isAllocator(Call, C))
    return;

  // Only track when the allocator return value is assigned to some lvalue.
  const MemRegion *LHSRegion = getAssignedLHSRegionForCall(Call, C);
  if (!LHSRegion)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<PendingAllocRegion>(LHSRegion->getBaseRegion());
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *Pending = State->get<PendingAllocRegion>();
  if (!Pending)
    return;

  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    // Not an expression; clear pending and move on.
    State = State->remove<PendingAllocRegion>();
    C.addTransition(State);
    return;
  }

  const Expr *CheckedExpr = nullptr;
  if (!isNullCheck(CondE, CheckedExpr, C)) {
    // Not an explicit NULL check; clear pending to avoid stale state.
    State = State->remove<PendingAllocRegion>();
    C.addTransition(State);
    return;
  }

  // Resolve the region of the checked expression.
  const MemRegion *CheckedReg = getMemRegionFromExpr(CheckedExpr, C);
  if (!CheckedReg) {
    // Unable to map; clear pending and continue.
    State = State->remove<PendingAllocRegion>();
    C.addTransition(State);
    return;
  }

  CheckedReg = CheckedReg->getBaseRegion();
  Pending = Pending->getBaseRegion();

  if (sameRegion(CheckedReg, Pending)) {
    // Correct NULL check on the newly allocated pointer.
    State = State->remove<PendingAllocRegion>();
    C.addTransition(State);
    return;
  }

  // Mismatch: the immediate NULL check is on a different pointer.
  reportMismatch(Condition, C);

  // Clear pending regardless to avoid cascading.
  State = State->remove<PendingAllocRegion>();
  C.addTransition(State);
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->remove<PendingAllocRegion>();
  C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->remove<PendingAllocRegion>();
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects mismatched NULL check immediately after allocation (checks a different pointer than the allocated one)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
