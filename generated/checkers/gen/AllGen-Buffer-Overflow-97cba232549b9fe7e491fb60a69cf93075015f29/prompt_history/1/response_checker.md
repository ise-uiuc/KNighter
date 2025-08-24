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
#include "clang/AST/Decl.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/OperationKinds.h"
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Off-by-one look-ahead array access", "Array bounds")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Helper: try to extract loop induction variable and upper bound from a for-statement condition
      bool getLoopVarAndBound(const ForStmt *FS, const VarDecl *&IVar, const Expr *&UB) const;

      // Helper: check if increment updates the same induction variable (i++, ++i, i += 1)
      bool isIncrementOfVar(const Stmt *Inc, const VarDecl *IVar, ASTContext &AC) const;

      // Helper: check if expression is DeclRef to given VarDecl
      static bool isDeclRefToVar(const Expr *E, const VarDecl *VD);

      // Helper: evaluate expression as integer constant
      static bool evalAsInt(const Expr *E, ASTContext &AC, llvm::APSInt &Res);

      // Helper: check whether an index expression is (i + 1) or (1 + i)
      bool isIPlusOne(const Expr *Idx, const VarDecl *IVar, ASTContext &AC) const;

      // Helper: check whether expression is (X - 1), RHS constant 1 (we don't care about X)
      bool isMinusOneExpr(const Expr *E, ASTContext &AC) const;

      // Helper: recursively check if a condition contains a guard implying i+1 < bound or i < bound - 1
      bool conditionContainsLookAheadGuard(const Expr *Cond, const VarDecl *IVar, ASTContext &AC) const;

      // Helper: find nearest enclosing IfStmt by walking AST parents
      const IfStmt *findNearestEnclosingIf(const Stmt *S, ASTContext &AC) const;

      // Analyze a ForStmt and possibly emit a report
      void analyzeForStmt(const ForStmt *FS, ASTContext &AC, BugReporter &BR) const;
};

bool SAGenTestChecker::isDeclRefToVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  return false;
}

bool SAGenTestChecker::evalAsInt(const Expr *E, ASTContext &AC, llvm::APSInt &Res) {
  if (!E) return false;
  Expr::EvalResult ER;
  if (E->EvaluateAsInt(ER, AC)) {
    Res = ER.Val.getInt();
    return true;
  }
  return false;
}

bool SAGenTestChecker::isIPlusOne(const Expr *Idx, const VarDecl *IVar, ASTContext &AC) const {
  if (!Idx || !IVar) return false;
  Idx = Idx->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Idx);
  if (!BO || BO->getOpcode() != BO_Add)
    return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  // Pattern: i + 1
  if (isDeclRefToVar(L, IVar)) {
    llvm::APSInt V;
    if (evalAsInt(R, AC, V) && V == 1)
      return true;
    if (const auto *IL = dyn_cast<IntegerLiteral>(R))
      return IL->getValue() == 1;
  }

  // Pattern: 1 + i
  if (isDeclRefToVar(R, IVar)) {
    llvm::APSInt V;
    if (evalAsInt(L, AC, V) && V == 1)
      return true;
    if (const auto *IL = dyn_cast<IntegerLiteral>(L))
      return IL->getValue() == 1;
  }

  return false;
}

bool SAGenTestChecker::isMinusOneExpr(const Expr *E, ASTContext &AC) const {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Sub)
    return false;

  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  llvm::APSInt V;
  if (evalAsInt(RHS, AC, V))
    return V == 1;

  if (const auto *IL = dyn_cast<IntegerLiteral>(RHS))
    return IL->getValue() == 1;

  return false;
}

bool SAGenTestChecker::conditionContainsLookAheadGuard(const Expr *Cond, const VarDecl *IVar, ASTContext &AC) const {
  if (!Cond || !IVar) return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    // For logical ops, check both sides
    if (BO->isLogicalOp()) {
      return conditionContainsLookAheadGuard(BO->getLHS(), IVar, AC) ||
             conditionContainsLookAheadGuard(BO->getRHS(), IVar, AC);
    }

    // Check relational ops for patterns
    BinaryOperatorKind Op = BO->getOpcode();
    if (Op == BO_LT || Op == BO_LE || Op == BO_GT || Op == BO_GE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      // (i + 1) < Bound  OR  Bound > (i + 1)
      if (isIPlusOne(L, IVar, AC) || isIPlusOne(R, IVar, AC))
        return true;

      // i < (Bound - 1)  OR  (Bound - 1) > i
      if (isDeclRefToVar(L, IVar) && isMinusOneExpr(R, AC))
        return true;
      if (isDeclRefToVar(R, IVar) && isMinusOneExpr(L, AC))
        return true;
    }

    // Recurse into arithmetic to find subpatterns
    return conditionContainsLookAheadGuard(BO->getLHS(), IVar, AC) ||
           conditionContainsLookAheadGuard(BO->getRHS(), IVar, AC);
  } else if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    return conditionContainsLookAheadGuard(UO->getSubExpr(), IVar, AC);
  }

  return false;
}

const IfStmt *SAGenTestChecker::findNearestEnclosingIf(const Stmt *S, ASTContext &AC) const {
  if (!S) return nullptr;
  const Stmt *Cur = S;
  for (;;) {
    DynTypedNode Node = DynTypedNode::create(*Cur);
    auto Parents = AC.getParents(Node);
    if (Parents.empty())
      break;

    // Look across parents: return first IfStmt if present, else continue upward using the first Stmt parent.
    for (const auto &P : Parents) {
      if (const auto *IS = P.get<IfStmt>())
        return IS;
    }

    // Default to continue with the first Stmt parent if any.
    const Stmt *Next = nullptr;
    for (const auto &P : Parents) {
      if (const auto *PS = P.get<Stmt>()) {
        Next = PS;
        break;
      }
    }
    if (!Next)
      break;
    Cur = Next;
  }
  return nullptr;
}

bool SAGenTestChecker::getLoopVarAndBound(const ForStmt *FS, const VarDecl *&IVar, const Expr *&UB) const {
  IVar = nullptr;
  UB = nullptr;
  if (!FS) return false;
  const Expr *Cond = FS->getCond();
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  BinaryOperatorKind Op = BO->getOpcode();
  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  // Pattern: i < UB
  if (Op == BO_LT) {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(L)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        IVar = VD;
        UB = R;
      }
    }
  }

  // Pattern: UB > i  (equivalent to i < UB)
  if (!IVar && Op == BO_GT) {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(R)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        IVar = VD;
        UB = L;
      }
    }
  }

  return IVar && UB;
}

bool SAGenTestChecker::isIncrementOfVar(const Stmt *Inc, const VarDecl *IVar, ASTContext &AC) const {
  if (!Inc || !IVar) return false;

  if (const auto *UO = dyn_cast<UnaryOperator>(Inc)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
      return isDeclRefToVar(UO->getSubExpr(), IVar);
    }
    return false;
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Inc)) {
    // Handle i += 1
    if (BO->getOpcode() == BO_AddAssign) {
      if (isDeclRefToVar(BO->getLHS(), IVar)) {
        llvm::APSInt V;
        if (evalAsInt(BO->getRHS(), AC, V) && V == 1)
          return true;
        if (const auto *IL = dyn_cast<IntegerLiteral>(BO->getRHS()->IgnoreParenImpCasts()))
          return IL->getValue() == 1;
      }
    }
    return false;
  }

  return false;
}

void SAGenTestChecker::analyzeForStmt(const ForStmt *FS, ASTContext &AC, BugReporter &BR) const {
  const VarDecl *IVar = nullptr;
  const Expr *UB = nullptr;

  // 1) Get loop var and bound: must match i < UB (or UB > i)
  if (!getLoopVarAndBound(FS, IVar, UB))
    return;

  // 2) Ensure increment updates IVar in a straightforward manner
  if (!isIncrementOfVar(FS->getInc(), IVar, AC))
    return;

  // 3) Traverse the loop body to find arr[i + 1]
  const Stmt *Body = FS->getBody();
  if (!Body)
    return;

  const ArraySubscriptExpr *OffendingASE = nullptr;

  class AccessFinder : public RecursiveASTVisitor<AccessFinder> {
    const VarDecl *IVar;
    ASTContext &AC;
    const SAGenTestChecker &Chk;
    const ArraySubscriptExpr *&Found;
    const ForStmt *FS;
  public:
    AccessFinder(const VarDecl *IV, ASTContext &Ctx, const SAGenTestChecker &C,
                 const ForStmt *F, const ArraySubscriptExpr *&Out)
      : IVar(IV), AC(Ctx), Chk(C), Found(Out), FS(F) {}

    bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
      if (Found) return true; // already found one, keep scanning but no need to re-check
      const Expr *Idx = ASE->getIdx();
      if (!Idx) return true;
      if (!Chk.isIPlusOne(Idx, IVar, AC))
        return true;

      // Check for a guarding if-condition near this access
      const IfStmt *IS = Chk.findNearestEnclosingIf(ASE, AC);
      bool Guarded = false;
      if (IS) {
        const Expr *Cond = IS->getCond();
        if (Cond && Chk.conditionContainsLookAheadGuard(Cond, IVar, AC))
          Guarded = true;
      }

      if (!Guarded) {
        Found = ASE;
      }
      return true;
    }
  };

  AccessFinder Finder(IVar, AC, *this, FS, OffendingASE);
  Finder.TraverseStmt(const_cast<Stmt*>(Body));

  if (!OffendingASE)
    return;

  // 4) Report once per offending loop
  PathDiagnosticLocation ELoc =
      PathDiagnosticLocation::createBegin(OffendingASE, BR.getSourceManager(), AC);
  auto R = std::make_unique<BasicBugReport>(
      *BT,
      "Off-by-one: loop uses 'i < bound' but accesses element at 'i + 1'. "
      "Use 'i < bound - 1' or guard the access.",
      ELoc);
  R->addRange(OffendingASE->getSourceRange());
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return;
  const Stmt *Body = FD->getBody();
  if (!Body) return;

  ASTContext &AC = Mgr.getASTContext();

  class ForFinder : public RecursiveASTVisitor<ForFinder> {
    ASTContext &AC;
    BugReporter &BR;
    const SAGenTestChecker &Chk;
  public:
    ForFinder(ASTContext &Ctx, BugReporter &B, const SAGenTestChecker &C) : AC(Ctx), BR(B), Chk(C) {}
    bool VisitForStmt(ForStmt *FS) {
      Chk.analyzeForStmt(FS, AC, BR);
      return true;
    }
  } Visitor(AC, BR, *this);

  Visitor.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one loops that access arr[i+1] while using i < bound",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
