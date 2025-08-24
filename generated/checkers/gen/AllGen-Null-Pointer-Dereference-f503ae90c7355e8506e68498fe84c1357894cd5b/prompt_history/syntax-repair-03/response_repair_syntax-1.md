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

// Program state: map possibly-NULL getter results to a "checked" flag.
// false: unchecked; true: checked.
REGISTER_MAP_WITH_PROGRAMSTATE(NullCkMap, const MemRegion*, bool)
// Program state: track pointer aliasing; map a region to its "root" region.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::Bind,
        check::Location,
        check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Dereference of possibly NULL capability pointer", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:
      // Helpers
      static bool isKnownPossiblyNullGetter(const CallEvent &Call, CheckerContext &C);
      static const MemRegion* findRootAlias(ProgramStateRef State, const MemRegion *R);
      static const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C);
      static ProgramStateRef setChecked(ProgramStateRef State, const MemRegion *R);
      void reportDeref(const Stmt *S, CheckerContext &C, StringRef Msg = StringRef()) const;

      template <typename E>
      static const E* findChild(const Stmt *S) {
        return findSpecificTypeInChildren<E>(S);
      }
};

bool SAGenTestChecker::isKnownPossiblyNullGetter(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  // Match exact function name as required.
  return ExprHasName(Origin, "mt76_connac_get_he_phy_cap", C);
}

const MemRegion* SAGenTestChecker::findRootAlias(ProgramStateRef State, const MemRegion *R) {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  while (true) {
    const MemRegion *const *NextPtr = State->get<PtrAliasMap>(Cur);
    if (!NextPtr)
      break;
    const MemRegion *Next = *NextPtr;
    if (!Next || Next == Cur)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

ProgramStateRef SAGenTestChecker::setChecked(ProgramStateRef State, const MemRegion *R) {
  if (!R)
    return State;
  R = R->getBaseRegion();
  const MemRegion *Root = findRootAlias(State, R);
  if (!Root)
    Root = R;
  const bool *Checked = State->get<NullCkMap>(Root);
  if (Checked && *Checked == false) {
    State = State->set<NullCkMap>(Root, true);
  }
  return State;
}

void SAGenTestChecker::reportDeref(const Stmt *S, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  StringRef Message = Msg.empty()
    ? "Dereference of possibly NULL capability pointer returned by mt76_connac_get_he_phy_cap"
    : Msg;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Message, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isKnownPossiblyNullGetter(Call, C))
    return;

  ProgramStateRef State = C.getState();

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const MemRegion *RetRegFromExpr = getMemRegionFromExpr(Origin, C);
  if (!RetRegFromExpr)
    return;

  RetRegFromExpr = RetRegFromExpr->getBaseRegion();
  if (!RetRegFromExpr)
    return;

  // Mark the getter result as "unchecked".
  State = State->set<NullCkMap>(RetRegFromExpr, false);
  // Make it its own root in alias map.
  State = State->set<PtrAliasMap>(RetRegFromExpr, RetRegFromExpr);

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track pointer aliasing: p2 = p1;
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (LHSReg) {
      if (const MemRegion *RHSReg = Val.getAsRegion()) {
        RHSReg = RHSReg->getBaseRegion();
        if (RHSReg) {
          const MemRegion *Root = findRootAlias(State, RHSReg);
          if (!Root)
            Root = RHSReg;
          // Only link if we track the root or RHS is already rooted.
          const bool *Tracked = State->get<NullCkMap>(Root);
          if (Tracked) {
            State = State->set<PtrAliasMap>(LHSReg, Root);
          }
        }
      }
    }
  }

  // Detect deref via address-of member: ve = &vc->field;
  // Look for '&' applied to an arrow member expression.
  const UnaryOperator *UO = findChild<UnaryOperator>(S);
  if (UO && UO->getOpcode() == UO_AddrOf) {
    const MemberExpr *ME = findChild<MemberExpr>(S);
    if (ME && ME->isArrow()) {
      const Expr *BaseE = ME->getBase();
      const MemRegion *BaseReg = getBaseRegionFromExpr(BaseE, C);
      if (BaseReg) {
        const MemRegion *Root = findRootAlias(State, BaseReg);
        if (!Root)
          Root = BaseReg;
        const bool *Checked = State->get<NullCkMap>(Root);
        if (Checked && *Checked == false) {
          reportDeref(S, C);
        }
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal L, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!S)
    return;

  const Expr *BaseE = nullptr;

  // Prefer MemberExpr with '->'
  if (const auto *ME = findChild<MemberExpr>(S)) {
    if (ME->isArrow())
      BaseE = ME->getBase();
  }

  // If not, check for explicit dereference '*p'
  if (!BaseE) {
    if (const auto *UO = findChild<UnaryOperator>(S)) {
      if (UO->getOpcode() == UO_Deref) {
        BaseE = UO->getSubExpr();
      }
    }
  }

  // If not, check for array subscripting 'p[i]'
  if (!BaseE) {
    if (const auto *ASE = findChild<ArraySubscriptExpr>(S)) {
      BaseE = ASE->getBase();
    }
  }

  if (!BaseE)
    return;

  const MemRegion *BaseReg = getBaseRegionFromExpr(BaseE, C);
  if (!BaseReg)
    return;

  const MemRegion *Root = findRootAlias(State, BaseReg);
  if (!Root)
    Root = BaseReg;

  const bool *Checked = State->get<NullCkMap>(Root);
  if (Checked && *Checked == false) {
    reportDeref(S, C);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  CondE = CondE->IgnoreParenCasts();

  // if (!p)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      if (const MemRegion *MR = getBaseRegionFromExpr(SubE, C)) {
        const MemRegion *Root = findRootAlias(State, MR);
        if (!Root)
          Root = MR;
        const bool *Tracked = State->get<NullCkMap>(Root);
        if (Tracked && *Tracked == false) {
          State = State->set<NullCkMap>(Root, true);
        }
      }
      C.addTransition(State);
      return;
    }
  }

  // if (p == NULL) or if (p != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                  Expr::NPC_ValueDependentIsNull);

      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull) PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull) PtrExpr = LHS;

      if (PtrExpr) {
        if (const MemRegion *MR = getBaseRegionFromExpr(PtrExpr, C)) {
          const MemRegion *Root = findRootAlias(State, MR);
          if (!Root)
            Root = MR;
          const bool *Tracked = State->get<NullCkMap>(Root);
          if (Tracked && *Tracked == false) {
            State = State->set<NullCkMap>(Root, true);
          }
        }
      }
      C.addTransition(State);
      return;
    }
  }

  // if (p)
  {
    if (const MemRegion *MR = getBaseRegionFromExpr(CondE, C)) {
      const MemRegion *Root = findRootAlias(State, MR);
      if (!Root)
        Root = MR;
      const bool *Tracked = State->get<NullCkMap>(Root);
      if (Tracked && *Tracked == false) {
        State = State->set<NullCkMap>(Root, true);
      }
    }
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of capability pointer returned by mt76_connac_get_he_phy_cap without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
