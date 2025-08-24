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
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state customizations
REGISTER_SET_WITH_PROGRAMSTATE(DevmMaybeNullSyms, SymbolRef)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrStatusMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall,
                                        check::Bind,
                                        check::BranchCondition,
                                        check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Possible NULL dereference (devm_kzalloc result)", "Memory error")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Self-defined helpers
      bool isDevmKzalloc(const CallEvent &Call, CheckerContext &C) const;

      const MemRegion *canonical(const MemRegion *R, ProgramStateRef State) const;

      ProgramStateRef markUnchecked(ProgramStateRef State, const MemRegion *R) const;
      ProgramStateRef markChecked(ProgramStateRef State, const MemRegion *R) const;

      bool isCheckedOrAliasedChecked(ProgramStateRef State, const MemRegion *R) const;
      bool isExplicitlyUnchecked(ProgramStateRef State, const MemRegion *R) const;

      // Try to extract the pointer expression being checked in a condition.
      const Expr *getCheckedPtrExprFromCondition(const Stmt *Condition, CheckerContext &C) const;

      void reportDerefWithoutCheck(const Stmt *S, CheckerContext &C) const;
};

// Helper: match devm_kzalloc by callee name using source text
bool SAGenTestChecker::isDevmKzalloc(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "devm_kzalloc", C);
}

const MemRegion *SAGenTestChecker::canonical(const MemRegion *R, ProgramStateRef State) const {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break; // cycle protection
    const MemRegion *Next = nullptr;
    if (const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur))
      Next = *NextPtr;
    if (!Next)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur ? Cur->getBaseRegion() : nullptr;
}

ProgramStateRef SAGenTestChecker::markUnchecked(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return State;
  const MemRegion *Base = R->getBaseRegion();
  const MemRegion *Root = canonical(Base, State);
  if (!Root)
    Root = Base;
  State = State->set<PtrStatusMap>(Base, false);
  State = State->set<PtrStatusMap>(Root, false);
  return State;
}

ProgramStateRef SAGenTestChecker::markChecked(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return State;
  const MemRegion *Base = R->getBaseRegion();
  const MemRegion *Root = canonical(Base, State);
  if (!Root)
    Root = Base;
  State = State->set<PtrStatusMap>(Base, true);
  State = State->set<PtrStatusMap>(Root, true);
  return State;
}

bool SAGenTestChecker::isCheckedOrAliasedChecked(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return false;
  const MemRegion *Base = R->getBaseRegion();
  const bool *CheckedBase = State->get<PtrStatusMap>(Base);
  if (CheckedBase && *CheckedBase)
    return true;
  const MemRegion *Root = canonical(Base, State);
  if (Root) {
    const bool *CheckedRoot = State->get<PtrStatusMap>(Root);
    if (CheckedRoot && *CheckedRoot)
      return true;
  }
  return false;
}

bool SAGenTestChecker::isExplicitlyUnchecked(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return false;
  const MemRegion *Base = R->getBaseRegion();
  const bool *CheckedBase = State->get<PtrStatusMap>(Base);
  if (CheckedBase && !*CheckedBase)
    return true;
  const MemRegion *Root = canonical(Base, State);
  if (Root) {
    const bool *CheckedRoot = State->get<PtrStatusMap>(Root);
    if (CheckedRoot && !*CheckedRoot)
      return true;
  }
  return false;
}

const Expr *SAGenTestChecker::getCheckedPtrExprFromCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return nullptr;

  // Pattern 1: if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      return UO->getSubExpr(); // do not strip implicit casts per guideline
    }
  }

  // Pattern 2: if (ptr == NULL) or if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        return RHS;
      if (RHSIsNull && !LHSIsNull)
        return LHS;
    }
  }

  // Pattern 3: if (ptr)
  // Treat the whole condition as pointer expression.
  return CondE;
}

void SAGenTestChecker::reportDerefWithoutCheck(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Dereference of devm_kzalloc() result without NULL check", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// PostCall: remember devm_kzalloc return symbol as maybe-null
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isDevmKzalloc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->add<DevmMaybeNullSyms>(Sym);
    C.addTransition(State);
  }
}

// Bind: mark LHS as unchecked when bound from devm_kzalloc return,
// and track pointer aliasing.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // Case 1: Binding devm_kzalloc's return symbol to a region => mark unchecked
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (State->contains<DevmMaybeNullSyms>(Sym)) {
      State = markUnchecked(State, LHSReg);
      State = State->remove<DevmMaybeNullSyms>(Sym);
      C.addTransition(State);
      return;
    }
  }

  // Case 2: Track aliases when assigning one pointer region to another.
  if (const MemRegion *RHSReg = Val.getAsRegion()) {
    RHSReg = RHSReg->getBaseRegion();
    if (RHSReg) {
      const MemRegion *Root = canonical(RHSReg, State);
      if (!Root)
        Root = RHSReg;
      // Map both sides to the same canonical root to avoid cycles and
      // allow checks to propagate.
      State = State->set<PtrAliasMap>(LHSReg, Root);
      State = State->set<PtrAliasMap>(RHSReg, Root);
      C.addTransition(State);
    }
  }
}

// BranchCondition: mark pointers as checked when we see a NULL-check
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CheckedExpr = getCheckedPtrExprFromCondition(Condition, C);
  if (!CheckedExpr) {
    C.addTransition(State);
    return;
  }

  const MemRegion *MR = getMemRegionFromExpr(CheckedExpr, C);
  if (MR) {
    MR = MR->getBaseRegion();
    if (MR) {
      State = markChecked(State, MR);
      C.addTransition(State);
      return;
    }
  }

  C.addTransition(State);
}

// Location: detect actual dereference via '->' or '*' and warn if unchecked.
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *BaseExpr = nullptr;

  // Try to find MemberExpr with '->'
  const MemberExpr *ME = dyn_cast_or_null<MemberExpr>(S);
  if (!ME)
    ME = findSpecificTypeInParents<MemberExpr>(S, C);
  if (ME && ME->isArrow()) {
    BaseExpr = ME->getBase();
  } else {
    // Try to find UnaryOperator '*'
    const UnaryOperator *UO = dyn_cast_or_null<UnaryOperator>(S);
    if (!UO)
      UO = findSpecificTypeInParents<UnaryOperator>(S, C);
    if (UO && UO->getOpcode() == UO_Deref) {
      BaseExpr = UO->getSubExpr();
    }
  }

  if (!BaseExpr)
    return;

  // First, if base is a symbol returned by devm_kzalloc and still not stored, warn.
  SVal BaseVal = State->getSVal(BaseExpr, C.getLocationContext());
  if (SymbolRef Sym = BaseVal.getAsSymbol()) {
    if (State->contains<DevmMaybeNullSyms>(Sym)) {
      reportDerefWithoutCheck(S, C);
      return;
    }
  }

  const MemRegion *MR = getMemRegionFromExpr(BaseExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  if (isCheckedOrAliasedChecked(State, MR))
    return;

  if (isExplicitlyUnchecked(State, MR)) {
    reportDerefWithoutCheck(S, C);
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of devm_kzalloc result without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
