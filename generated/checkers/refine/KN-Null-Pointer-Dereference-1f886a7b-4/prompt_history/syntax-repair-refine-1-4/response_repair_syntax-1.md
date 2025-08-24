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

  // Returns true if the given symbol is provably non-NULL at this program point.
  bool isProvenNonNull(SymbolRef Sym, CheckerContext &C) const;

  // Recursively collect symbols that are explicitly checked against NULL
  // inside a condition expression (including inside wrappers), to optionally
  // reduce tracking noise. We do NOT treat bare "if (ptr)" as a check here.
  void collectExplicitNullCheckSyms(const Expr *E,
                                    CheckerContext &C,
                                    llvm::SmallVectorImpl<SymbolRef> &Out) const;

  void reportBug(CheckerContext &C, const Stmt *S) const;
};

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

  // Fallback: derive from location region.
  if (const MemRegion *MR = Loc.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }

  return nullptr;
}

bool SAGenTestChecker::isProvenNonNull(SymbolRef Sym, CheckerContext &C) const {
  if (!Sym)
    return false;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();

  // Build "Sym == 0" with the appropriate pointer type.
  SVal SymV = SVB.makeSymbolVal(Sym);
  QualType Ty = Sym->getType();
  if (Ty.isNull())
    Ty = C.getASTContext().VoidPtrTy;
  SVal NullV = SVB.makeZeroVal(Ty);

  DefinedOrUnknownSVal IsNull = SVB.evalEQ(State, SymV, NullV);

  ProgramStateRef StNull = State->assume(IsNull, true);
  ProgramStateRef StNonNull = State->assume(IsNull, false);

  // If the "null" assumption is infeasible, then it's proven non-null.
  if (!StNull && StNonNull)
    return true;

  return false;
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
  // Only track explicit calls to devm_kzalloc.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    if (ID->getName() != "devm_kzalloc")
      return;
  } else {
    return;
  }

  // Ensure we're dealing with a pointer result.
  if (!Call.getResultType()->isPointerType())
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->add<UncheckedDevmPtrSyms>(Sym);
    C.addTransition(State);
  }
}

// Collect symbols that are explicitly checked against NULL inside E.
// This handles nested wrappers, logical ops, and common forms like !p, p == NULL, p != NULL.
// Bare "p" is intentionally ignored to avoid suppressing true positives when code does not guard.
void SAGenTestChecker::collectExplicitNullCheckSyms(const Expr *E,
                                                    CheckerContext &C,
                                                    llvm::SmallVectorImpl<SymbolRef> &Out) const {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      if (Sub) {
        SVal SV = C.getState()->getSVal(Sub, C.getLocationContext());
        if (SymbolRef S = SV.getAsSymbol())
          Out.push_back(S);
        // Also recurse into sub to catch forms like !(p == NULL)
        collectExplicitNullCheckSyms(Sub, C, Out);
      }
      return;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isLogicalOp()) {
      collectExplicitNullCheckSyms(BO->getLHS(), C, Out);
      collectExplicitNullCheckSyms(BO->getRHS(), C, Out);
      return;
    }

    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = BO->getRHS();
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = BO->getLHS();

      if (PtrExpr) {
        SVal SV = C.getState()->getSVal(PtrExpr, C.getLocationContext());
        if (SymbolRef S = SV.getAsSymbol())
          Out.push_back(S);
      }

      // Recurse to catch any nested forms.
      collectExplicitNullCheckSyms(LHS, C, Out);
      collectExplicitNullCheckSyms(RHS, C, Out);
      return;
    }
  }

  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    for (const Expr *Arg : CE->arguments())
      collectExplicitNullCheckSyms(Arg, C, Out);
    return;
  }

  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    collectExplicitNullCheckSyms(CO->getCond(), C, Out);
    collectExplicitNullCheckSyms(CO->getTrueExpr(), C, Out);
    collectExplicitNullCheckSyms(CO->getFalseExpr(), C, Out);
    return;
  }

  if (const auto *SE = dyn_cast<StmtExpr>(E)) {
    if (const auto *CS = dyn_cast_or_null<CompoundStmt>(SE->getSubStmt())) {
      if (!CS->body_empty()) {
        if (const auto *LastE = dyn_cast<Expr>(CS->body_back()))
          collectExplicitNullCheckSyms(LastE, C, Out);
      }
    }
    return;
  }

  // Note: We intentionally do NOT treat a bare pointer expression as a NULL check here.
  // That is handled by path constraints at dereference time.
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Optional early cleanup to reduce tracking noise when the condition explicitly checks NULL
  // even if wrapped in macros/calls. We avoid removing on plain "if (p)" patterns.
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  llvm::SmallVector<SymbolRef, 4> CheckedSyms;
  collectExplicitNullCheckSyms(CondE, C, CheckedSyms);
  if (CheckedSyms.empty())
    return;

  bool Changed = false;
  for (SymbolRef S : CheckedSyms) {
    if (State->contains<UncheckedDevmPtrSyms>(S)) {
      // Be conservative: don't remove here to avoid suppressing true positives on the wrong branch.
      // Instead, keep the state as-is and rely on path constraints at dereference time.
      // If you'd like to prune state early for performance, uncomment the removal below
      // only if you also implement branch-sensitive updates (e.g., via evalAssume).
      // State = State->remove<UncheckedDevmPtrSyms>(S); Changed = true;
      (void)S;
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
  if (!State->contains<UncheckedDevmPtrSyms>(BaseSym))
    return;

  // If the pointer is provably non-NULL on this path, do not report.
  if (isProvenNonNull(BaseSym, C)) {
    ProgramStateRef NewState = State->remove<UncheckedDevmPtrSyms>(BaseSym);
    C.addTransition(NewState);
    return;
  }

  // Otherwise, the pointer may be NULL. Report possible dereference.
  reportBug(C, S);
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
```
