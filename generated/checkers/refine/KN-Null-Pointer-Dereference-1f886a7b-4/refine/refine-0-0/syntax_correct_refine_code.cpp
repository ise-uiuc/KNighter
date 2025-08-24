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

  // Try to extract a devm_kzalloc-return symbol that is being "checked" in a condition.
  // This understands wrappers like __builtin_expect(!!expr, ...) produced by likely/unlikely.
  SymbolRef tryGetCheckedSymbolFromCondition(const Expr *CondE, CheckerContext &C) const;

  // Strip parens/implicit casts.
  const Expr *stripParensAndCasts(const Expr *E) const {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  // If CondE is a call to __builtin_expect, return its first argument (stripped),
  // otherwise return CondE (stripped).
  const Expr *unwrapBuiltinExpect(const Expr *CondE) const {
    CondE = stripParensAndCasts(CondE);
    if (const auto *CE = dyn_cast_or_null<CallExpr>(CondE)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        if (const IdentifierInfo *II = FD->getIdentifier()) {
          if (II->getName() == "__builtin_expect" && CE->getNumArgs() > 0) {
            return stripParensAndCasts(CE->getArg(0));
          }
        }
      }
    }
    return CondE;
  }

  // Peel any number of logical-nots that may be introduced by !! wrappers.
  const Expr *peelLogicalNots(const Expr *E) const {
    E = stripParensAndCasts(E);
    while (const auto *UO = dyn_cast_or_null<UnaryOperator>(E)) {
      if (UO->getOpcode() != UO_LNot)
        break;
      E = stripParensAndCasts(UO->getSubExpr());
    }
    return E;
  }

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

SymbolRef SAGenTestChecker::tryGetCheckedSymbolFromCondition(const Expr *CondE,
                                                             CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  if (!CondE)
    return nullptr;

  // Unwrap likely/unlikely: __builtin_expect(!!(expr), ...)
  const Expr *E = unwrapBuiltinExpect(CondE);

  // Strip any number of logical-nots added by '!!'
  E = peelLogicalNots(E);

  // Handle binary comparisons: (ptr == NULL) or (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = stripParensAndCasts(BO->getLHS());
      const Expr *RHS = stripParensAndCasts(BO->getRHS());
      if (LHS && RHS) {
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
          if (SymbolRef Sym = SV.getAsSymbol())
            return Sym;
          if (const MemRegion *MR = SV.getAsRegion()) {
            MR = MR->getBaseRegion();
            if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
              return SR->getSymbol();
          }
          return nullptr;
        }
      }
    }
  }

  // Handle direct pointer truthiness: if (ptr)
  E = stripParensAndCasts(E);
  if (E && E->getType()->isPointerType()) {
    SVal SV = State->getSVal(E, LCtx);
    if (SymbolRef Sym = SV.getAsSymbol())
      return Sym;
    if (const MemRegion *MR = SV.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
        return SR->getSymbol();
    }
  }

  // Handle: if (!ptr) already handled via peeling and then pointer truthiness above.

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

  // Track only devm_kzalloc results by callee identifier.
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID || ID->getName() != "devm_kzalloc")
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

  // Try to extract the symbol that is being null-checked in this condition.
  if (SymbolRef TargetSym = tryGetCheckedSymbolFromCondition(CondE, C)) {
    if (State->contains<UncheckedDevmPtrSyms>(TargetSym)) {
      State = State->remove<UncheckedDevmPtrSyms>(TargetSym);
      C.addTransition(State);
    }
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
