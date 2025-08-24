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

  // Helpers to analyze branch conditions and strip wrappers.
  const Expr *stripParensCastsAndBuiltinExpect(const Expr *E) const;
  SymbolRef getPointerSymbolFromExpr(const Expr *E, CheckerContext &C) const;
  bool isNullPtrConstant(const Expr *E, CheckerContext &C) const;

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

// Strip wrappers commonly seen in kernel boolean expressions:
// - Parentheses and implicit casts
// - __builtin_expect(...) introduced by likely()/unlikely() macros
const Expr *SAGenTestChecker::stripParensCastsAndBuiltinExpect(const Expr *E) const {
  if (!E)
    return E;

  E = E->IgnoreParenImpCasts();

  // Unwrap any number of nested __builtin_expect(...) layers.
  while (true) {
    E = E->IgnoreParenImpCasts();
    const auto *CE = dyn_cast<CallExpr>(E);
    if (!CE)
      break;

    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      break;

    IdentifierInfo *II = FD->getIdentifier();
    if (!II)
      break;

    // Match by name to avoid extra includes; GCC/Clang both use __builtin_expect.
    if (II->getName().equals("__builtin_expect")) {
      if (CE->getNumArgs() > 0) {
        E = CE->getArg(0)->IgnoreParenImpCasts();
        continue; // Keep unwrapping if nested
      }
    }
    break;
  }

  return E;
}

// Try to extract the SymbolRef of a pointer expression used in a condition.
// Handles chains like !!ptr or !!!ptr by peeling UO_LNot down to the base expr.
SymbolRef SAGenTestChecker::getPointerSymbolFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  E = stripParensCastsAndBuiltinExpect(E);

  // Peel chains of logical not (!! or more).
  while (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot)
      E = UO->getSubExpr()->IgnoreParenImpCasts();
    else
      break;
  }

  // Obtain the symbol the analyzer associates with the expression.
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

bool SAGenTestChecker::isNullPtrConstant(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  return E->IgnoreParenImpCasts()->isNullPointerConstant(C.getASTContext(),
                                                         Expr::NPC_ValueDependentIsNull);
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

  // Only track direct calls to devm_kzalloc (use callee identifier, not text).
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    if (!ID->getName().equals("devm_kzalloc"))
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

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();
  (void)LCtx;

  SymbolRef TargetSym = nullptr;

  // First try to unwrap builtins/paren/casts to the "real" condition.
  const Expr *CoreE = stripParensCastsAndBuiltinExpect(CondE);

  // Handle: if (!ptr) / if (!!ptr) / if (ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CoreE)) {
    if (UO->getOpcode() == UO_LNot) {
      // Get underlying pointer symbol even for chains of UO_LNot.
      TargetSym = getPointerSymbolFromExpr(UO, C);
    }
  }

  // Handle: if (ptr == NULL) or if (ptr != NULL)
  if (!TargetSym) {
    if (const auto *BO = dyn_cast<BinaryOperator>(CoreE)) {
      BinaryOperator::Opcode Op = BO->getOpcode();
      if (Op == BO_EQ || Op == BO_NE) {
        const Expr *LHS = BO->getLHS();
        const Expr *RHS = BO->getRHS();
        if (LHS && RHS) {
          bool LHSIsNull = isNullPtrConstant(LHS, C);
          bool RHSIsNull = isNullPtrConstant(RHS, C);
          const Expr *PtrExpr = nullptr;
          if (LHSIsNull && !RHSIsNull)
            PtrExpr = RHS;
          else if (RHSIsNull && !LHSIsNull)
            PtrExpr = LHS;

          if (PtrExpr)
            TargetSym = getPointerSymbolFromExpr(PtrExpr, C);
        }
      }
    }
  }

  // Handle: if (ptr) and likely/unlikely-wrapped truthiness checks.
  if (!TargetSym) {
    TargetSym = getPointerSymbolFromExpr(CoreE, C);
  }

  // If the condition clearly references our tracked pointer in a nullness check,
  // consider it "checked" and remove it from the unchecked set.
  if (TargetSym && State->contains<UncheckedDevmPtrSyms>(TargetSym)) {
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
