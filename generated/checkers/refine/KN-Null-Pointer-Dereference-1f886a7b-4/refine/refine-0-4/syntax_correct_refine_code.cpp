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

  void reportBug(CheckerContext &C, const Stmt *S) const;

  // Helper: given an expression, collect symbols that are "null-checked" within it.
  // This recognizes:
  //  - ptr == NULL / ptr != NULL
  //  - !ptr
  //  - likely(ptr) / unlikely(ptr)  -> treat argument as truthiness null-check
  //  - IS_ERR_OR_NULL(ptr)          -> treat as a null-check
  //  - WARN_ON(!ptr) / BUG_ON(!ptr) -> recurse into the first arg to look for !ptr or comparisons
  void collectNullCheckSymbols(const Expr *E, CheckerContext &C,
                               llvm::SmallVectorImpl<SymbolRef> &OutSyms,
                               bool AllowPurePtrTruthiness = true) const;

  // Helper: get symbol from a direct pointer expression (DeclRef, MemberExpr base, etc.)
  SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) const;

  // Helper: check if expression is a null pointer constant.
  bool isNullPtrConst(const Expr *E, CheckerContext &C) const;
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

bool SAGenTestChecker::isNullPtrConst(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  return E->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNull);
}

SymbolRef SAGenTestChecker::getSymbolFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
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

void SAGenTestChecker::collectNullCheckSymbols(const Expr *E, CheckerContext &C,
                                               llvm::SmallVectorImpl<SymbolRef> &OutSyms,
                                               bool AllowPurePtrTruthiness) const {
  if (!E) return;
  E = E->IgnoreParenImpCasts();

  // 1) Binary operators
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LAnd || Op == BO_LOr) {
      collectNullCheckSymbols(BO->getLHS(), C, OutSyms, AllowPurePtrTruthiness);
      collectNullCheckSymbols(BO->getRHS(), C, OutSyms, AllowPurePtrTruthiness);
      return;
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      bool LHSIsNull = isNullPtrConst(LHS, C);
      bool RHSIsNull = isNullPtrConst(RHS, C);
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;

      if (PtrExpr) {
        if (SymbolRef S = getSymbolFromExpr(PtrExpr, C))
          OutSyms.push_back(S);
      }
      return;
    }

    // Comma operator: condition's value is RHS
    if (Op == BO_Comma) {
      collectNullCheckSymbols(BO->getRHS(), C, OutSyms, AllowPurePtrTruthiness);
      return;
    }
  }

  // 2) Unary operators
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      // if (!ptr) { ... }
      const Expr *SubE = UO->getSubExpr();
      if (SymbolRef S = getSymbolFromExpr(SubE, C)) {
        OutSyms.push_back(S);
        return;
      }
      // If direct symbol is not obtainable, still recurse; might be !IS_ERR_OR_NULL(ptr)
      collectNullCheckSymbols(SubE, C, OutSyms, AllowPurePtrTruthiness);
      return;
    }
    // Other unary ops: ignore.
  }

  // 3) Specific call wrappers commonly used in the kernel
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    // If the textual source contains specific wrappers, special-handle their first arg.
    bool HasWarnOn = ExprHasName(E, "WARN_ON", C) || ExprHasName(E, "WARN_ON_ONCE", C);
    bool HasBugOn = ExprHasName(E, "BUG_ON", C);
    bool HasLikely = ExprHasName(E, "likely", C) || ExprHasName(E, "unlikely", C);
    bool HasIsErrOrNull = ExprHasName(E, "IS_ERR_OR_NULL", C);

    if ((HasWarnOn || HasBugOn) && CE->getNumArgs() > 0) {
      // Only recurse into the first argument; we will pick up !ptr or comparisons within it.
      collectNullCheckSymbols(CE->getArg(0), C, OutSyms, /*AllowPurePtrTruthiness*/false);
      return;
    }

    if (HasLikely && CE->getNumArgs() > 0) {
      // likely(ptr) or unlikely(ptr) acts like a truthiness check of the first argument.
      const Expr *Arg0 = CE->getArg(0);
      // For likely/unlikely, allow pure ptr truthiness.
      collectNullCheckSymbols(Arg0, C, OutSyms, /*AllowPurePtrTruthiness*/true);
      // Also handle ptr directly if it is just a DeclRefExpr or similar.
      if (AllowPurePtrTruthiness) {
        if (SymbolRef S = getSymbolFromExpr(Arg0, C))
          OutSyms.push_back(S);
      }
      return;
    }

    if (HasIsErrOrNull && CE->getNumArgs() > 0) {
      // IS_ERR_OR_NULL(ptr) => treat as null-check of the argument.
      if (SymbolRef S = getSymbolFromExpr(CE->getArg(0), C))
        OutSyms.push_back(S);
      return;
    }

    // For all other calls: do not recurse, to avoid incorrectly treating arbitrary
    // function arguments as null-checks.
    return;
  }

  // 4) Pure truthiness check: if (ptr) { ... }
  if (AllowPurePtrTruthiness) {
    if (SymbolRef S = getSymbolFromExpr(E, C)) {
      // Only treat as null-check if the expression is a raw pointer-like symbol.
      QualType T = E->getType();
      if (!T.isNull() && (T->isPointerType() || T->isReferenceType()))
        OutSyms.push_back(S);
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<SymbolRef, 4> CheckedSyms;
  collectNullCheckSymbols(CondE, C, CheckedSyms, /*AllowPurePtrTruthiness*/true);

  if (CheckedSyms.empty())
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
