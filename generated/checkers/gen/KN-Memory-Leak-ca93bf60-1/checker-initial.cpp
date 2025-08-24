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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: live temporary allocations that must be freed (e.g., from kmalloc/nvmem_cell_read)
REGISTER_SET_WITH_PROGRAMSTATE(LiveTempAllocs, const MemRegion *)
// Program state: last temporary allocation region
REGISTER_TRAIT_WITH_PROGRAMSTATE(LastTempAllocRegion, const MemRegion *)
// Program state: recent LHS targets of devm_* allocator assignments
REGISTER_SET_WITH_PROGRAMSTATE(RecentDevmTargets, const MemRegion *)
// Program state: simple pointer aliasing (dest -> canonical src)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::Bind,
      check::BranchCondition
    > {

   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Memory leak on error path", "Memory")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  static bool isMustFreeAllocator(const CallEvent &Call, CheckerContext &C);
  static bool isDevmAllocator(const CallEvent &Call, CheckerContext &C);
  const MemRegion* getAssignedLHSRegionOfCall(const CallEvent &Call, CheckerContext &C) const;
  const MemRegion* resolveAlias(const MemRegion *R, ProgramStateRef State) const;
  const MemRegion* extractPtrRegionFromNullCheck(const Stmt *Condition, CheckerContext &C) const;

  void reportLeak(CheckerContext &C, const Stmt *Site) const;
};

// Return true for allocators that require explicit kfree/kvfree.
bool SAGenTestChecker::isMustFreeAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "nvmem_cell_read", C) ||
         ExprHasName(E, "kmalloc", C) ||
         ExprHasName(E, "kzalloc", C) ||
         ExprHasName(E, "kcalloc", C) ||
         ExprHasName(E, "krealloc", C) ||
         ExprHasName(E, "kmemdup", C) ||
         ExprHasName(E, "kstrdup", C);
}

// Return true for devm_* allocators.
bool SAGenTestChecker::isDevmAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E) return false;
  return ExprHasName(E, "devm_kmalloc", C) ||
         ExprHasName(E, "devm_kzalloc", C) ||
         ExprHasName(E, "devm_kcalloc", C) ||
         ExprHasName(E, "devm_krealloc", C) ||
         ExprHasName(E, "devm_kmemdup", C) ||
         ExprHasName(E, "devm_kstrdup", C);
}

// Get the LHS region of an assignment where this call is on the RHS:  LHS = call(...);
const MemRegion* SAGenTestChecker::getAssignedLHSRegionOfCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Orig = Call.getOriginExpr();
  if (!Orig)
    return nullptr;

  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(Orig, C);
  if (!BO)
    return nullptr;
  if (BO->getOpcode() != BO_Assign)
    return nullptr;

  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(LHS, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

// Resolve alias chain using PtrAliasMap.
const MemRegion* SAGenTestChecker::resolveAlias(const MemRegion *R, ProgramStateRef State) const {
  if (!R) return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break; // cycle
    auto Next = State->get<PtrAliasMap>(Cur);
    if (!Next) break;
    Cur = (*Next)->getBaseRegion();
  }
  return Cur;
}

// Extract pointer region being NULL-checked in a simple condition:
// - if (!ptr)
// - if (ptr == NULL) or if (ptr != NULL)
// - optionally if (ptr)
const MemRegion* SAGenTestChecker::extractPtrRegionFromNullCheck(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) return nullptr;

  CondE = CondE->IgnoreParenCasts();

  // if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr();
      if (!SubE) return nullptr;
      const MemRegion *MR = getMemRegionFromExpr(SubE, C);
      if (!MR) return nullptr;
      return MR->getBaseRegion();
    }
  }

  // if (ptr == NULL) or if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      if (!LHS || !RHS) return nullptr;

      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);

      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull) PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull) PtrExpr = LHS;

      if (PtrExpr) {
        const MemRegion *MR = getMemRegionFromExpr(PtrExpr, C);
        if (!MR) return nullptr;
        return MR->getBaseRegion();
      }
    }
  }

  // if (ptr)
  {
    const MemRegion *MR = getMemRegionFromExpr(CondE, C);
    if (MR) return MR->getBaseRegion();
  }

  return nullptr;
}

void SAGenTestChecker::reportLeak(CheckerContext &C, const Stmt *Site) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Leak of temporary buffer on allocation failure path; missing kfree", N);
  if (Site)
    R->addRange(Site->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track must-free temporary allocations assigned to an LHS variable.
  if (isMustFreeAllocator(Call, C)) {
    const MemRegion *LHS = getAssignedLHSRegionOfCall(Call, C);
    if (LHS) {
      LHS = LHS->getBaseRegion();
      const MemRegion *Canon = resolveAlias(LHS, State);
      if (Canon) {
        State = State->add<LiveTempAllocs>(Canon);
        State = State->set<LastTempAllocRegion>(Canon);
        C.addTransition(State);
      }
    }
    return;
  }

  // Track devm_* allocator targets on assignment.
  if (isDevmAllocator(Call, C)) {
    const MemRegion *LHS = getAssignedLHSRegionOfCall(Call, C);
    if (LHS) {
      LHS = LHS->getBaseRegion();
      const MemRegion *Canon = resolveAlias(LHS, State);
      if (Canon) {
        State = State->add<RecentDevmTargets>(Canon);
        C.addTransition(State);
      }
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *E = Call.getOriginExpr();
  if (!E) return;

  // Intercept frees: kfree/kvfree/vfree(ptr)
  if (ExprHasName(E, "kfree", C) || ExprHasName(E, "kvfree", C) || ExprHasName(E, "vfree", C)) {
    if (Call.getNumArgs() < 1) return;

    const Expr *Arg0 = Call.getArgExpr(0);
    if (!Arg0) return;

    const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
    if (!MR) return;
    MR = MR->getBaseRegion();

    const MemRegion *Canon = resolveAlias(MR, State);
    if (!Canon) return;

    if (State->contains<LiveTempAllocs>(Canon)) {
      State = State->remove<LiveTempAllocs>(Canon);
      const MemRegion *Last = State->get<LastTempAllocRegion>();
      if (Last == Canon) {
        State = State->set<LastTempAllocRegion>(nullptr);
      }
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *Dest = Loc.getAsRegion();
  if (!Dest) return;
  Dest = Dest->getBaseRegion();
  if (!Dest) return;

  const MemRegion *Src = Val.getAsRegion();
  if (!Src) {
    // Optional: could clear alias mapping when binding a non-region value.
    return;
  }
  Src = Src->getBaseRegion();

  const MemRegion *CanonSrc = resolveAlias(Src, State);
  if (!CanonSrc) return;

  State = State->set<PtrAliasMap>(Dest, CanonSrc);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Extract pointer being NULL-checked in the condition.
  const MemRegion *PtrReg = extractPtrRegionFromNullCheck(Condition, C);
  if (!PtrReg) {
    C.addTransition(State);
    return;
  }

  PtrReg = PtrReg->getBaseRegion();
  const MemRegion *CanonPtr = resolveAlias(PtrReg, State);
  if (!CanonPtr) {
    C.addTransition(State);
    return;
  }

  // Only proceed if pointer is a recent target of a devm_* allocator assignment.
  if (!State->contains<RecentDevmTargets>(CanonPtr)) {
    C.addTransition(State);
    return;
  }

  // Check if this condition's 'then' branch immediately returns.
  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS) {
    C.addTransition(State);
    return;
  }

  const Stmt *ThenS = IfS->getThen();
  if (!ThenS) {
    C.addTransition(State);
    return;
  }

  const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
  if (!RS) {
    C.addTransition(State);
    return;
  }

  // Now see if there's a live temporary allocation outstanding.
  const MemRegion *Last = State->get<LastTempAllocRegion>();
  if (!Last) {
    C.addTransition(State);
    return;
  }

  if (State->contains<LiveTempAllocs>(Last)) {
    // We are about to return due to devm_* allocation failure, but a temporary
    // buffer allocated earlier is still live and not freed.
    reportLeak(C, RS);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing kfree of a temporary buffer when returning on devm_* alloc failure",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
