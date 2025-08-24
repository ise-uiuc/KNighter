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

  // Returns the underlying symbol from an SVal or its base region if symbolic.
  SymbolRef getBaseSymbolFromSVal(SVal V) const;

  // Strip wrappers like __builtin_expect and ignore parens/casts.
  const Expr *stripExpectLike(const Expr *E) const;

  // Try to extract a pointer symbol that is being checked for truthiness/nullness.
  SymbolRef extractPointerSymFromCond(const Expr *E, CheckerContext &C) const;

  void reportBug(CheckerContext &C, const Stmt *S) const;
};

SymbolRef SAGenTestChecker::getBaseSymbolFromSVal(SVal V) const {
  if (SymbolRef Sym = V.getAsSymbol())
    return Sym;
  if (const MemRegion *MR = V.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }
  return nullptr;
}

const Expr *SAGenTestChecker::stripExpectLike(const Expr *E) const {
  if (!E)
    return nullptr;

  const Expr *Cur = E->IgnoreParenImpCasts();
  // Strip __builtin_expect(...) and __builtin_expect_with_probability(...)
  while (const auto *CE = dyn_cast<CallExpr>(Cur)) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      break;

    // Compare by identifier name to avoid relying on Builtin::ID enumerators.
    if (const IdentifierInfo *II = FD->getIdentifier()) {
      StringRef Name = II->getName();
      if ((Name == "__builtin_expect" ||
           Name == "__builtin_expect_with_probability") &&
          CE->getNumArgs() >= 1) {
        Cur = CE->getArg(0)->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }

  return Cur->IgnoreParenImpCasts();
}

SymbolRef SAGenTestChecker::extractPointerSymFromCond(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;

  const Expr *Cond = stripExpectLike(E);
  if (!Cond)
    return nullptr;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // Handle logical operators by searching either side.
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    // Explicit null comparisons.
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
      if (PtrExpr) {
        SVal SV = State->getSVal(PtrExpr, LCtx);
        return getBaseSymbolFromSVal(SV);
      }
    }

    // Logical composition: recurse.
    if (Op == BO_LOr || Op == BO_LAnd) {
      if (SymbolRef S = extractPointerSymFromCond(BO->getLHS(), C))
        return S;
      if (SymbolRef S = extractPointerSymFromCond(BO->getRHS(), C))
        return S;
    }
  }

  // Handle negation: if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenImpCasts();
      // e.g., !ptr
      SVal SV = State->getSVal(SubE, LCtx);
      if (SymbolRef S = getBaseSymbolFromSVal(SV))
        return S;
      // Or ! (ptr == NULL) -> already handled by BO_EQ above when not wrapped.
      if (const auto *SBO = dyn_cast<BinaryOperator>(SubE)) {
        return extractPointerSymFromCond(SBO, C);
      }
    }
  }

  // Handle truthiness: if (ptr)
  // Only consider if expression is of pointer type or decays to one.
  if (Cond->getType()->isPointerType()) {
    SVal SV = State->getSVal(Cond, LCtx);
    if (SymbolRef S = getBaseSymbolFromSVal(SV))
      return S;
  }

  return nullptr;
}

SymbolRef SAGenTestChecker::getDereferencedBaseSymbol(const Stmt *S, SVal Loc,
                                                      CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // Case 1: p->field (MemberExpr with arrow). Extract 'p'.
  if (const auto *ME = dyn_cast_or_null<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *BaseE = ME->getBase();
      if (BaseE) {
        SVal BaseV = State->getSVal(BaseE, LCtx);
        if (SymbolRef Sym = getBaseSymbolFromSVal(BaseV))
          return Sym;
      }
    }
  }

  // Case 2: *p
  if (const auto *UO = dyn_cast_or_null<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *BaseE = UO->getSubExpr();
      if (BaseE) {
        SVal BaseV = State->getSVal(BaseE, LCtx);
        if (SymbolRef Sym = getBaseSymbolFromSVal(BaseV))
          return Sym;
      }
    }
  }

  // Fallback: derive from location region.
  if (SymbolRef Sym = getBaseSymbolFromSVal(Loc))
    return Sym;

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

  // Only track devm_kzalloc results.
  if (!ExprHasName(OriginExpr, "devm_kzalloc", C))
    return;

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

  ProgramStateRef State = C.getState();
  SymbolRef TargetSym = extractPointerSymFromCond(CondE, C);

  if (TargetSym && State->contains<UncheckedDevmPtrSyms>(TargetSym)) {
    // Mark as checked once we see a truthiness/nullness test for this pointer.
    State = State->remove<UncheckedDevmPtrSyms>(TargetSym);
    C.addTransition(State);
  }
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
```
