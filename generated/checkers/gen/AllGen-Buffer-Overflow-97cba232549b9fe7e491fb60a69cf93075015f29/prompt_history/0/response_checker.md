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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/APSInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No extra program states are needed for this checker.
namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Off-by-one array access", "Array bounds")) {}

      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Try to extract a constant array size from the base expression of an array subscript.
      bool getConstArraySizeFromBase(const Expr *BaseE, llvm::APInt &ArrSize, CheckerContext &C) const;

      // Parse an index expression into "LoopVar +/- Const". Return true if matched and Const (K) >= 1.
      bool parseIndexOffset(const Expr *IdxE, const VarDecl *&LoopVarVD, long long &K,
                            CheckerContext &C) const;

      // Analyze the loop condition and extract the bound expression if it matches "i < Bound" or "Bound > i"
      // with the same loop variable.
      bool getLoopBoundFromFor(const ForStmt *FS, const VarDecl *LoopVarVD,
                               const Expr *&BoundE) const;

      // Try to evaluate a constant expression to APSInt. Wrapper around provided helper.
      bool evalToInt(llvm::APSInt &Res, const Expr *E, CheckerContext &C) const {
        return EvaluateExprToInt(Res, E, C);
      }

      // Check for a guarding if-statement inside the loop that ensures "i + K < Bound"
      // via patterns "i + K2 < Bound" with K2 >= K, or "i < Bound - K2" with K2 >= K.
      bool hasGuardingIfInsideLoop(const ArraySubscriptExpr *ASE, const ForStmt *FS,
                                   const VarDecl *LoopVarVD, long long K,
                                   const llvm::APSInt &BoundVal, CheckerContext &C) const;

      // Helper: compare two expressions by constant integer value equality.
      bool constExprsEqualByIntValue(const Expr *A, const Expr *B, CheckerContext &C) const;
};

bool SAGenTestChecker::getConstArraySizeFromBase(const Expr *BaseE, llvm::APInt &ArrSize,
                                                 CheckerContext &C) const {
  if (!BaseE) return false;
  const Expr *E = BaseE->IgnoreParenImpCasts();
  QualType T = E->getType();

  // Directly from the expression type
  if (const auto *CAT = dyn_cast<ConstantArrayType>(T.getTypePtr())) {
    ArrSize = CAT->getSize();
    return true;
  }

  // Try member's declared type if it's a field access.
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      QualType FT = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr())) {
        ArrSize = CAT->getSize();
        return true;
      }
    }
  }

  // Fall back to provided helper for DeclRefExpr of arrays
  if (getArraySizeFromExpr(ArrSize, E))
    return true;

  return false;
}

bool SAGenTestChecker::parseIndexOffset(const Expr *IdxE, const VarDecl *&LoopVarVD,
                                        long long &K, CheckerContext &C) const {
  LoopVarVD = nullptr;
  K = 0;
  if (!IdxE) return false;

  const Expr *E = IdxE->IgnoreParenImpCasts();

  // Case: i + C or C + i or i - C
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op != BO_Add && Op != BO_Sub)
      return false;

    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

    const DeclRefExpr *VarSide = nullptr;
    const Expr *ConstSide = nullptr;
    bool VarOnLeft = false;

    if ((VarSide = dyn_cast<DeclRefExpr>(L))) {
      VarOnLeft = true;
      ConstSide = R;
    } else if ((VarSide = dyn_cast<DeclRefExpr>(R))) {
      VarOnLeft = false;
      ConstSide = L;
    } else {
      return false;
    }

    const VarDecl *VD = dyn_cast<VarDecl>(VarSide->getDecl());
    if (!VD)
      return false;

    llvm::APSInt Val;
    if (!evalToInt(Val, ConstSide, C))
      return false;

    long long ConstK = 0;
    if (Val.isSigned())
      ConstK = Val.getSExtValue();
    else
      ConstK = static_cast<long long>(Val.getZExtValue());

    if (Op == BO_Add) {
      // i + C or C + i
      LoopVarVD = VD;
      K = ConstK;
    } else {
      // subtraction: i - C
      if (!VarOnLeft)
        return false; // C - i is not our pattern
      LoopVarVD = VD;
      K = -ConstK;
    }

    // Only care about positive offsets
    if (K >= 1)
      return true;

    return false;
  }

  // Pure variable: i (no offset) - not our target
  if (const auto *DR = dyn_cast<DeclRefExpr>(E)) {
    (void)DR;
    return false;
  }

  // Not a supported pattern
  return false;
}

bool SAGenTestChecker::getLoopBoundFromFor(const ForStmt *FS, const VarDecl *LoopVarVD,
                                           const Expr *&BoundE) const {
  BoundE = nullptr;
  if (!FS || !LoopVarVD)
    return false;

  const Stmt *CondS = FS->getCond();
  if (!CondS)
    return false;

  const Expr *CondE = dyn_cast<Expr>(CondS);
  if (!CondE)
    return false;

  CondE = CondE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return false;

  // i < Bound
  if (BO->getOpcode() == BO_LT) {
    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const auto *DL = dyn_cast<DeclRefExpr>(L);
    if (!DL) return false;
    const VarDecl *LVD = dyn_cast<VarDecl>(DL->getDecl());
    if (LVD != LoopVarVD)
      return false;
    BoundE = BO->getRHS();
    return BoundE != nullptr;
  }

  // Bound > i
  if (BO->getOpcode() == BO_GT) {
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
    const auto *DR = dyn_cast<DeclRefExpr>(R);
    if (!DR) return false;
    const VarDecl *RVD = dyn_cast<VarDecl>(DR->getDecl());
    if (RVD != LoopVarVD)
      return false;
    BoundE = BO->getLHS();
    return BoundE != nullptr;
  }

  return false;
}

bool SAGenTestChecker::constExprsEqualByIntValue(const Expr *A, const Expr *B,
                                                 CheckerContext &C) const {
  if (!A || !B) return false;
  llvm::APSInt VA, VB;
  if (!evalToInt(VA, A->IgnoreParenImpCasts(), C))
    return false;
  if (!evalToInt(VB, B->IgnoreParenImpCasts(), C))
    return false;
  // Compare values (treat as unsigned to avoid sign issues)
  return VA.getLimitedValue() == VB.getLimitedValue();
}

bool SAGenTestChecker::hasGuardingIfInsideLoop(const ArraySubscriptExpr *ASE, const ForStmt *FS,
                                               const VarDecl *LoopVarVD, long long K,
                                               const llvm::APSInt &BoundVal,
                                               CheckerContext &C) const {
  if (!ASE || !FS || !LoopVarVD)
    return false;

  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(ASE, C);
  if (!IfS)
    return false;

  // Ensure this IfStmt is within the same for-loop's body (ancestor relation)
  const ForStmt *AncFor = findSpecificTypeInParents<ForStmt>(IfS, C);
  if (AncFor != FS)
    return false;

  const Expr *Cond = IfS->getCond();
  if (!Cond)
    return false;

  const Expr *CE = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(CE);
  if (!BO)
    return false;

  // Only handle strict less-than guards for now to reduce false positives.
  if (BO->getOpcode() != BO_LT)
    return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  // Evaluate BoundRHS numeric value for comparing with loop bound.
  llvm::APSInt RHSVal;
  if (!evalToInt(RHSVal, R, C))
    return false;

  // If Right side equals the same bound value, handle "i + K2 < Bound"
  if (RHSVal.getLimitedValue() == BoundVal.getLimitedValue()) {
    const VarDecl *Var2 = nullptr;
    long long K2 = 0;
    if (parseIndexOffset(L, Var2, K2, C) && Var2 == LoopVarVD) {
      if (K2 >= K)
        return true;
    }
  }

  // Handle "i < Bound - K2"
  if (const auto *BOR = dyn_cast<BinaryOperator>(R)) {
    if (BOR->getOpcode() == BO_Sub) {
      const Expr *RL = BOR->getLHS()->IgnoreParenImpCasts();
      const Expr *RR = BOR->getRHS()->IgnoreParenImpCasts();

      // Check RL equals bound by value
      if (!constExprsEqualByIntValue(RL, R, C)) {
        // We compared R to itself; instead compare RL to the original loop bound value.
        llvm::APSInt RLVal;
        if (!evalToInt(RLVal, RL, C))
          return false;
        if (RLVal.getLimitedValue() != BoundVal.getLimitedValue())
          return false;
      }

      llvm::APSInt K2Val;
      if (!evalToInt(K2Val, RR, C))
        return false;

      unsigned long long K2 = K2Val.getLimitedValue();
      // Left side must be the loop variable alone.
      if (const auto *DL = dyn_cast<DeclRefExpr>(L)) {
        const VarDecl *LV = dyn_cast<VarDecl>(DL->getDecl());
        if (LV == LoopVarVD) {
          if (K2 >= static_cast<unsigned long long>(K))
            return true;
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only act on array subscripts
  const auto *ASE = dyn_cast_or_null<ArraySubscriptExpr>(S);
  if (!ASE)
    return;

  const Expr *BaseE = ASE->getBase();
  const Expr *IdxE  = ASE->getIdx();
  if (!BaseE || !IdxE)
    return;

  // Step B: Parse index "i +/- K" with K >= 1
  const VarDecl *LoopVarVD = nullptr;
  long long K = 0;
  if (!parseIndexOffset(IdxE, LoopVarVD, K, C))
    return;

  // Step C: Find enclosing for-statement and extract loop bound
  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(ASE, C);
  if (!FS)
    return;

  const Expr *BoundE = nullptr;
  if (!getLoopBoundFromFor(FS, LoopVarVD, BoundE))
    return;

  // Step D: Get array size of the base
  llvm::APInt ArrSize(64, 0);
  if (!getConstArraySizeFromBase(BaseE, ArrSize, C))
    return;

  // Step E: Evaluate loop bound and compare to array size
  llvm::APSInt BoundVal;
  if (!evalToInt(BoundVal, BoundE->IgnoreParenImpCasts(), C))
    return;

  unsigned long long NArr = ArrSize.getLimitedValue();
  unsigned long long NBound = BoundVal.getLimitedValue();

  if (NArr != NBound)
    return; // Only warn when loop upper bound equals array length

  // Step F: Look for a guarding if-statement inside the loop
  if (hasGuardingIfInsideLoop(ASE, FS, LoopVarVD, K, BoundVal, C))
    return;

  // Step G: Report the bug
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Loop iterates to last index while accessing arr[i+1] (off-by-one OOB).", N);
  R->addRange(ASE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one out-of-bounds when looping with i < N but accessing arr[i+1]",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
