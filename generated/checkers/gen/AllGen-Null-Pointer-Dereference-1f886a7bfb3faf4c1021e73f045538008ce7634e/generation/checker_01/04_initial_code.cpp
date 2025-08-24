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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: set of symbols returned from devm_kzalloc that may be NULL
REGISTER_SET_WITH_PROGRAMSTATE(DevmNullableSyms, SymbolRef)
// Program state: map regions (lvalues) holding tracked symbols to that symbol
REGISTER_MAP_WITH_PROGRAMSTATE(RegionToSym, const MemRegion *, SymbolRef)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall, check::Bind, check::BranchCondition, check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unchecked devm_kzalloc() result", "Null Dereference")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool isDevmKzalloc(const CallEvent &Call, CheckerContext &C);
      static const Expr *getPtrExprInCondition(const Stmt *Cond, CheckerContext &C);
      static ProgramStateRef markCheckedIfTracked(ProgramStateRef State, const Expr *E, CheckerContext &C);
      static const Expr *getBaseExprFromDeref(const Stmt *S);
};

bool SAGenTestChecker::isDevmKzalloc(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "devm_kzalloc", C);
}

const Expr *SAGenTestChecker::getPtrExprInCondition(const Stmt *Cond, CheckerContext &C) {
  if (!Cond)
    return nullptr;
  const Expr *CondE = dyn_cast<Expr>(Cond);
  if (!CondE)
    return nullptr;

  // if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      return UO->getSubExpr(); // do not IgnoreImpCasts before region extraction
    }
  }

  // if (ptr == NULL) or if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      if (!LHS || !RHS)
        return nullptr;

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

  // if (ptr)
  return CondE;
}

ProgramStateRef SAGenTestChecker::markCheckedIfTracked(ProgramStateRef State, const Expr *E, CheckerContext &C) {
  if (!E)
    return State;

  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return State;

  MR = MR->getBaseRegion();
  if (!MR)
    return State;

  if (const SymbolRef *SymPtr = State->get<RegionToSym>(MR)) {
    SymbolRef Sym = *SymPtr;
    if (State->contains<DevmNullableSyms>(Sym)) {
      State = State->remove<DevmNullableSyms>(Sym);
    }
  }
  return State;
}

// Find base pointer expression that is being dereferenced in statement S
const Expr *SAGenTestChecker::getBaseExprFromDeref(const Stmt *S) {
  if (!S)
    return nullptr;

  // Look for '->'
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME && ME->isArrow()) {
      return ME->getBase(); // do not strip implicit casts here
    }
  }

  // Look for '*ptr'
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO && UO->getOpcode() == UO_Deref) {
      return UO->getSubExpr();
    }
  }

  // Look for 'ptr[index]' where base is a pointer (not array lvalue)
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    if (ASE) {
      QualType BT = ASE->getBase()->getType();
      if (!BT.isNull() && BT->isPointerType()) {
        return ASE->getBase();
      }
    }
  }

  return nullptr;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isDevmKzalloc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    // Mark this returned symbol as possibly NULL (unchecked)
    State = State->add<DevmNullableSyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  bool Updated = false;

  // Case 1: RHS is a symbol directly (e.g., from devm_kzalloc return)
  if (SymbolRef RHSym = Val.getAsSymbol()) {
    if (State->contains<DevmNullableSyms>(RHSym)) {
      State = State->set<RegionToSym>(LHSReg, RHSym);
      Updated = true;
    }
  }

  // Case 2: RHS is an expression referring to a region that already holds a tracked symbol
  const Expr *RHSExpr = nullptr;
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      RHSExpr = BO->getRHS();
    }
  } else if (const auto *DS = dyn_cast_or_null<DeclStmt>(S)) {
    // Handle simple declarations with initializer: int *p = q;
    if (DS->isSingleDecl()) {
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (const Expr *Init = VD->getInit())
          RHSExpr = Init;
      }
    }
  }

  if (RHSExpr) {
    const MemRegion *RHSReg = getMemRegionFromExpr(RHSExpr, C);
    if (RHSReg) {
      RHSReg = RHSReg->getBaseRegion();
      if (RHSReg) {
        if (const SymbolRef *HeldSym = State->get<RegionToSym>(RHSReg)) {
          // Only propagate if that symbol is still considered possibly null
          if (State->contains<DevmNullableSyms>(*HeldSym)) {
            State = State->set<RegionToSym>(LHSReg, *HeldSym);
            Updated = true;
          }
        }
      }
    }
  }

  // If not updated and LHS had an old mapping, clear it to avoid stale associations
  if (!Updated) {
    if (State->get<RegionToSym>(LHSReg)) {
      State = State->remove<RegionToSym>(LHSReg);
      Updated = true;
    }
  }

  if (Updated)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *PtrExpr = getPtrExprInCondition(Condition, C);
  if (!PtrExpr) {
    C.addTransition(State);
    return;
  }

  State = markCheckedIfTracked(State, PtrExpr, C);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Try to find the base pointer expression being dereferenced in S
  const Expr *Base = getBaseExprFromDeref(S);
  if (!Base)
    return;

  const MemRegion *BaseReg = getMemRegionFromExpr(Base, C);
  if (!BaseReg)
    return;

  BaseReg = BaseReg->getBaseRegion();
  if (!BaseReg)
    return;

  const SymbolRef *SymPtr = State->get<RegionToSym>(BaseReg);
  if (!SymPtr)
    return;

  SymbolRef Sym = *SymPtr;
  if (!State->contains<DevmNullableSyms>(Sym))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked devm_kzalloc() result may be NULL", N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of devm_kzalloc() result without a NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
