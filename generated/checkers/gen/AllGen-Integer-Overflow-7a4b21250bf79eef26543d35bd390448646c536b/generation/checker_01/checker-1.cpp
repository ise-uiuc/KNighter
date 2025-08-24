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

// Map the symbol produced by roundup_pow_of_two(...) to its call site.
REGISTER_MAP_WITH_PROGRAMSTATE(RoundupSymMap, SymbolRef, const CallExpr*)

namespace {

class SAGenTestChecker : public Checker<
    check::Bind,
    check::BranchCondition
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker()
        : BT(new BugType(this,
                         "Unreliable overflow check with roundup_pow_of_two",
                         "API Misuse")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      static bool isULong32(const CheckerContext &C);
      static bool isZeroExpr(const Expr *E, CheckerContext &C);
      static const CallExpr* getRoundupCallFromExpr(const Expr *E, CheckerContext &C);
      static const CallExpr* getRoundupCallFromStmt(const Stmt *S, CheckerContext &C);
      void report(const Stmt *Anchor, CheckerContext &C) const;
};

bool SAGenTestChecker::isULong32(const CheckerContext &C) {
  const ASTContext &ACtx = C.getASTContext();
  return ACtx.getTypeSize(ACtx.UnsignedLongTy) == 32;
}

bool SAGenTestChecker::isZeroExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, E, C))
    return false;
  return Res == 0;
}

// If E is a call to roundup_pow_of_two, return it; else nullptr.
const CallExpr* SAGenTestChecker::getRoundupCallFromExpr(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (ExprHasName(CE, "roundup_pow_of_two", C))
      return CE;
  }
  return nullptr;
}

// Find a CallExpr to roundup_pow_of_two within S (search children).
const CallExpr* SAGenTestChecker::getRoundupCallFromStmt(const Stmt *S, CheckerContext &C) {
  if (!S) return nullptr;
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (CE && ExprHasName(CE, "roundup_pow_of_two", C))
    return CE;
  return nullptr;
}

void SAGenTestChecker::report(const Stmt *Anchor, CheckerContext &C) const {
  if (!BT) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unreliable overflow check: testing roundup_pow_of_two result against 0 on 32-bit.",
      N);

  if (Anchor)
    R->addRange(Anchor->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // Record bindings of symbols produced by roundup_pow_of_two(...)
  ProgramStateRef State = C.getState();

  // Find a direct call to roundup_pow_of_two in the RHS expression context.
  const CallExpr *CE = getRoundupCallFromStmt(S, C);
  if (!CE)
    return;

  // We only proceed if the bound value is a symbol we can track.
  SymbolRef Sym = Val.getAsSymbol();
  if (!Sym)
    return;

  State = State->set<RoundupSymMap>(Sym, CE);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!isULong32(C))
    return;

  const Expr *Cond = dyn_cast_or_null<Expr>(Condition);
  if (!Cond)
    return;
  Cond = Cond->IgnoreParenImpCasts();

  ProgramStateRef State = C.getState();

  // Case 1: if (!E)
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *E = UO->getSubExpr()->IgnoreParenImpCasts();

      // Direct: if (!roundup_pow_of_two(...))
      if (const CallExpr *CE = getRoundupCallFromExpr(E, C)) {
        report(Condition, C);
        return;
      }
      // Indirect: if (!n) where n was assigned from roundup_pow_of_two(...)
      SVal SV = State->getSVal(E, C.getLocationContext());
      if (SymbolRef Sym = SV.getAsSymbol()) {
        const CallExpr *Orig = State->get<RoundupSymMap>(Sym);
        if (Orig) {
          report(Condition, C);
          return;
        }
      }
    }
  }
  // Case 2: if (E == 0) or if (0 == E)
  else if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      // Check RHS == 0
      if (isZeroExpr(RHS, C)) {
        // Direct: if (roundup_pow_of_two(...) == 0)
        if (const CallExpr *CE = getRoundupCallFromExpr(LHS, C)) {
          report(Condition, C);
          return;
        }
        // Indirect: if (n == 0) with n from roundup_pow_of_two(...)
        SVal SV = State->getSVal(LHS, C.getLocationContext());
        if (SymbolRef Sym = SV.getAsSymbol()) {
          const CallExpr *Orig = State->get<RoundupSymMap>(Sym);
          if (Orig) {
            report(Condition, C);
            return;
          }
        }
      }
      // Check 0 == LHS
      if (isZeroExpr(LHS, C)) {
        if (const CallExpr *CE = getRoundupCallFromExpr(RHS, C)) {
          report(Condition, C);
          return;
        }
        SVal SV = State->getSVal(RHS, C.getLocationContext());
        if (SymbolRef Sym = SV.getAsSymbol()) {
          const CallExpr *Orig = State->get<RoundupSymMap>(Sym);
          if (Orig) {
            report(Condition, C);
            return;
          }
        }
      }
    }
  }

  // No state change; no need to add transition.
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unreliable overflow checks using roundup_pow_of_two result against 0 on 32-bit",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
