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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track unchecked symbols returned by devm_kzalloc.
REGISTER_SET_WITH_PROGRAMSTATE(UncheckedDevmPtrSyms, SymbolRef)

namespace {

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::BranchCondition,
      check::Location
    > {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Possible NULL dereference", "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Extract the base pointer symbol that is being dereferenced by statement S.
  SymbolRef getDereferencedBaseSymbol(const Stmt *S, SVal Loc, CheckerContext &C) const;

  // Helpers for finding null-checks embedded in conditions (including inside wrapper calls).
  enum class CheckContext { ConditionTop, InsideCall };

  SymbolRef getSymbolForExpr(const Expr *E, CheckerContext &C) const;

  bool isNullPointerConstantExpr(const Expr *E, CheckerContext &C) const;

  bool collectNullCheckSymbols(const Expr *E, CheckerContext &C,
                               llvm::SmallVectorImpl<SymbolRef> &OutSyms,
                               CheckContext Ctx) const;

  void reportBug(CheckerContext &C, const Stmt *S) const;
};

SymbolRef SAGenTestChecker::getSymbolForExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();
  SVal SV = State->getSVal(E, LCtx);
  if (SymbolRef Sym = SV.getAsSymbol())
    return Sym;
  if (const MemRegion *MR = SV.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }
  return nullptr;
}

bool SAGenTestChecker::isNullPointerConstantExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  return E->IgnoreParenImpCasts()->isNullPointerConstant(
      C.getASTContext(), Expr::NPC_ValueDependentIsNull);
}

bool SAGenTestChecker::collectNullCheckSymbols(const Expr *E, CheckerContext &C,
                                               llvm::SmallVectorImpl<SymbolRef> &OutSyms,
                                               CheckContext Ctx) const {
  if (!E) return false;

  E = E->IgnoreParenImpCasts();

  // Pattern: !ptr or !(ptr == NULL) etc.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      // Recurse into the sub-expression; allow both direct pointer and comparisons.
      return collectNullCheckSymbols(UO->getSubExpr(), C, OutSyms, Ctx);
    }
    // Other unary ops are not considered a null-check.
    return false;
  }

  // Pattern: ptr == NULL or ptr != NULL
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      if (LHS && RHS) {
        bool LNull = isNullPointerConstantExpr(LHS, C);
        bool RNull = isNullPointerConstantExpr(RHS, C);
        const Expr *PtrExpr = nullptr;
        if (LNull && !RNull) PtrExpr = RHS;
        else if (RNull && !LNull) PtrExpr = LHS;

        if (PtrExpr) {
          if (SymbolRef Sym = getSymbolForExpr(PtrExpr, C)) {
            OutSyms.push_back(Sym);
            return true;
          }
        }
      }
    }
    return false;
  }

  // Pattern: direct pointer used as condition (top-level only, e.g. if (ptr))
  if (Ctx == CheckContext::ConditionTop) {
    // Using a pointer in a boolean context counts as a check.
    if (SymbolRef Sym = getSymbolForExpr(E, C)) {
      OutSyms.push_back(Sym);
      return true;
    }
  }

  // Pattern: wrapper call in a condition, e.g. if (WARN_ON(!ptr)) or if (unlikely(!ptr))
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    bool Any = false;
    // Only consider explicit null-check patterns in arguments.
    for (const Expr *Arg : CE->arguments()) {
      // Inside a call: be strict. Accept only explicit null-check shapes (!ptr, ptr == NULL).
      Any |= collectNullCheckSymbols(Arg, C, OutSyms, CheckContext::InsideCall);
    }
    return Any;
  }

  // Not a recognized null-check pattern.
  return false;
}

SymbolRef SAGenTestChecker::getDereferencedBaseSymbol(const Stmt *S, SVal Loc,
                                                      CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // Case 1: p->field
  if (const auto *ME = dyn_cast_or_null<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *BaseE = ME->getBase();
      if (BaseE) {
        SVal BaseV = State->getSVal(BaseE, LCtx);
        if (SymbolRef Sym = BaseV.getAsSymbol())
          return Sym;
        if (const MemRegion *MR = BaseV.getAsRegion()) {
          MR = MR->getBaseRegion();
          if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
            return SR->getSymbol();
        }
      }
    }
  }

  // Case 2: *p
  if (const auto *UO = dyn_cast_or_null<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *BaseE = UO->getSubExpr();
      if (BaseE) {
        SVal BaseV = State->getSVal(BaseE, LCtx);
        if (SymbolRef Sym = BaseV.getAsSymbol())
          return Sym;
        if (const MemRegion *MR = BaseV.getAsRegion()) {
          MR = MR->getBaseRegion();
          if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
            return SR->getSymbol();
        }
      }
    }
  }

  // Fallback: derive from location region (e.g., array/pointer indexing).
  if (const MemRegion *MR = Loc.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }

  return nullptr;
}

void SAGenTestChecker::reportBug(CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "devm_kzalloc() result may be NULL and is dereferenced without check", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Only track devm_kzalloc results using callee identifier, not by source text.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    if (ID->getName() != "devm_kzalloc")
      return;
  } else {
    return;
  }

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->add<UncheckedDevmPtrSyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<SymbolRef, 4> CheckedSyms;
  // Collect any symbols that are being checked for null in the condition.
  if (!collectNullCheckSymbols(CondE, C, CheckedSyms, CheckContext::ConditionTop))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;
  for (SymbolRef S : CheckedSyms) {
    if (S && State->contains<UncheckedDevmPtrSyms>(S)) {
      State = State->remove<UncheckedDevmPtrSyms>(S);
      Changed = true;
    }
  }
  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  SymbolRef BaseSym = getDereferencedBaseSymbol(S, Loc, C);
  if (!BaseSym)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<UncheckedDevmPtrSyms>(BaseSym)) {
    reportBug(C, S);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect dereference of devm_kzalloc() result without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
