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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostStmt<ArraySubscriptExpr>> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "LUT index may exceed bound", "Array bounds")) {}

      void checkPostStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

   private:

      // Check if base expression of array subscript matches (...)->tf_pts.{red|green|blue}
      static bool matchTfPtsColorChain(const Expr *BaseE,
                                       std::string &ColorName,
                                       const FieldDecl *&ColorFD,
                                       const ConstantArrayType *&ArrTy);

      // Collect VarDecls referenced in an expression.
      static void collectReferencedVars(const Expr *E,
                                        llvm::SmallPtrSet<const VarDecl *, 4> &Vars);

      // Check if an expression references any of the given variables.
      static bool exprReferencesAnyVar(const Expr *E,
                                       const llvm::SmallPtrSet<const VarDecl *, 4> &Vars);

      // Check whether the given condition provides a guard ensuring idx < ArrSize (or <= ArrSize-1).
      static bool conditionGuardsIndex(const Expr *CondE,
                                       const llvm::SmallPtrSet<const VarDecl *, 4> &IndexVars,
                                       uint64_t ArrSize,
                                       CheckerContext &C);

      // Try to find an enclosing condition that guards the index.
      static bool hasGuardingAncestorCondition(const Stmt *Site,
                                               const llvm::SmallPtrSet<const VarDecl *, 4> &IndexVars,
                                               uint64_t ArrSize,
                                               CheckerContext &C);

      void reportOOB(const ArraySubscriptExpr *ASE, StringRef Color, CheckerContext &C) const;
};

bool SAGenTestChecker::matchTfPtsColorChain(const Expr *BaseE,
                                            std::string &ColorName,
                                            const FieldDecl *&ColorFD,
                                            const ConstantArrayType *&ArrTy) {
  if (!BaseE)
    return false;

  const Expr *E = BaseE->IgnoreParenImpCasts();

  const auto *MEColor = dyn_cast<MemberExpr>(E);
  if (!MEColor)
    return false;

  const auto *FDColor = dyn_cast<FieldDecl>(MEColor->getMemberDecl());
  if (!FDColor)
    return false;

  StringRef Name = FDColor->getName();
  if (!(Name == "red" || Name == "green" || Name == "blue"))
    return false;

  const Expr *TfBase = MEColor->getBase();
  if (!TfBase)
    return false;

  TfBase = TfBase->IgnoreParenImpCasts();
  const auto *METf = dyn_cast<MemberExpr>(TfBase);
  if (!METf)
    return false;

  const auto *FDTf = dyn_cast<FieldDecl>(METf->getMemberDecl());
  if (!FDTf)
    return false;

  if (FDTf->getName() != "tf_pts")
    return false;

  // Extract the array type of color field: should be a ConstantArrayType
  QualType FT = FDColor->getType();
  const Type *Ty = FT.getTypePtrOrNull();
  if (!Ty)
    return false;

  const auto *CAT = dyn_cast<ConstantArrayType>(Ty);
  if (!CAT)
    return false;

  ColorName = Name.str();
  ColorFD = FDColor;
  ArrTy = CAT;
  return true;
}

void SAGenTestChecker::collectReferencedVars(const Expr *E,
                                             llvm::SmallPtrSet<const VarDecl *, 4> &Vars) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      Vars.insert(VD);
    return;
  }

  // Recurse into children
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child))
      collectReferencedVars(CE, Vars);
  }
}

bool SAGenTestChecker::exprReferencesAnyVar(const Expr *E,
                                            const llvm::SmallPtrSet<const VarDecl *, 4> &Vars) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return Vars.count(VD);
    return false;
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      if (exprReferencesAnyVar(CE, Vars))
        return true;
    }
  }
  return false;
}

static bool evalToUInt64(const Expr *E, CheckerContext &C, uint64_t &Out) {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, E, C))
    return false;
  if (Res.isSigned()) {
    if (Res.isNegative())
      return false;
    Out = static_cast<uint64_t>(Res.getSExtValue());
  } else {
    Out = Res.getZExtValue();
  }
  return true;
}

bool SAGenTestChecker::conditionGuardsIndex(const Expr *CondE,
                                            const llvm::SmallPtrSet<const VarDecl *, 4> &IndexVars,
                                            uint64_t ArrSize,
                                            CheckerContext &C) {
  if (!CondE)
    return false;

  const Expr *E = CondE->IgnoreParenCasts();

  // Direct binary operator
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    // Case 1: var < N or var <= N
    if (exprReferencesAnyVar(LHS, IndexVars)) {
      uint64_t N;
      if (evalToUInt64(RHS, C, N)) {
        if (Op == BO_LT && N == ArrSize)
          return true;
        if (Op == BO_LE && N == (ArrSize - (ArrSize ? 1 : 0)))
          return ArrSize > 0;
      }
    }

    // Case 2: N > var or N >= var
    if (exprReferencesAnyVar(RHS, IndexVars)) {
      uint64_t N;
      if (evalToUInt64(LHS, C, N)) {
        if (Op == BO_GT && N == ArrSize)
          return true;
        if (Op == BO_GE && N == (ArrSize - (ArrSize ? 1 : 0)))
          return ArrSize > 0;
      }
    }

    // Recurse deeper for compound conditions: (A && B) etc.
    if (conditionGuardsIndex(LHS, IndexVars, ArrSize, C))
      return true;
    if (conditionGuardsIndex(RHS, IndexVars, ArrSize, C))
      return true;

    return false;
  }

  // Fallback: if the condition references both the index var and TRANSFER_FUNC_POINTS, consider it guarded.
  if (exprReferencesAnyVar(E, IndexVars) && ExprHasName(E, "TRANSFER_FUNC_POINTS", C))
    return true;

  // Recurse into subexpressions
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      if (conditionGuardsIndex(CE, IndexVars, ArrSize, C))
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::hasGuardingAncestorCondition(const Stmt *Site,
                                                    const llvm::SmallPtrSet<const VarDecl *, 4> &IndexVars,
                                                    uint64_t ArrSize,
                                                    CheckerContext &C) {
  // ForStmt
  if (const auto *FS = findSpecificTypeInParents<ForStmt>(Site, C)) {
    if (conditionGuardsIndex(FS->getCond(), IndexVars, ArrSize, C))
      return true;
  }

  // WhileStmt
  if (const auto *WS = findSpecificTypeInParents<WhileStmt>(Site, C)) {
    if (conditionGuardsIndex(WS->getCond(), IndexVars, ArrSize, C))
      return true;
  }

  // DoStmt
  if (const auto *DS = findSpecificTypeInParents<DoStmt>(Site, C)) {
    if (conditionGuardsIndex(DS->getCond(), IndexVars, ArrSize, C))
      return true;
  }

  // IfStmt
  if (const auto *IS = findSpecificTypeInParents<IfStmt>(Site, C)) {
    if (conditionGuardsIndex(IS->getCond(), IndexVars, ArrSize, C))
      return true;
  }

  return false;
}

void SAGenTestChecker::reportOOB(const ArraySubscriptExpr *ASE, StringRef Color, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "Index may exceed LUT bound when accessing tf_pts.";
  Msg += Color;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(ASE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  if (!ASE)
    return;

  // Match output_tf->tf_pts.{red|green|blue}[idx]
  std::string ColorName;
  const FieldDecl *ColorFD = nullptr;
  const ConstantArrayType *ArrTy = nullptr;
  if (!matchTfPtsColorChain(ASE->getBase(), ColorName, ColorFD, ArrTy))
    return;

  // Obtain array size
  llvm::APInt SizeAP = ArrTy->getSize();
  uint64_t ArrSize = SizeAP.getLimitedValue(UINT64_MAX);
  if (ArrSize == 0)
    return;

  const Expr *IdxE = ASE->getIdx();
  if (!IdxE)
    return;
  IdxE = IdxE->IgnoreParenImpCasts();

  // 1) Try constant evaluation
  llvm::APSInt IdxConst;
  if (EvaluateExprToInt(IdxConst, IdxE, C)) {
    int64_t IdxS = IdxConst.isSigned() ? IdxConst.getSExtValue()
                                       : static_cast<int64_t>(IdxConst.getZExtValue());
    if (IdxS >= 0 && static_cast<uint64_t>(IdxS) >= ArrSize) {
      reportOOB(ASE, ColorName, C);
      return;
    }
    // If constant and clearly within bound, consider safe.
    return;
  }

  // 2) Try to infer symbolic upper bound
  ProgramStateRef State = C.getState();
  SVal IdxSV = State->getSVal(IdxE, C.getLocationContext());
  if (SymbolRef Sym = IdxSV.getAsSymbol()) {
    if (const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C)) {
      uint64_t MaxU = MaxVal->isSigned()
                          ? (MaxVal->isNegative() ? 0ULL
                                                  : static_cast<uint64_t>(MaxVal->getSExtValue()))
                          : MaxVal->getZExtValue();
      if (MaxU >= ArrSize) {
        reportOOB(ASE, ColorName, C);
        return;
      } else {
        // Max strictly less than ArrSize -> safe
        return;
      }
    }
  }

  // 3) Heuristic: attempt to find guarding ancestor conditions comparing index vs TRANSFER_FUNC_POINTS / array size.
  llvm::SmallPtrSet<const VarDecl *, 4> IndexVars;
  collectReferencedVars(IdxE, IndexVars);
  if (hasGuardingAncestorCondition(ASE, IndexVars, ArrSize, C)) {
    // Consider guarded; do not warn.
    return;
  }

  // 4) Could not prove bounded and no guard found: warn.
  reportOOB(ASE, ColorName, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing bounds check when indexing tf_pts.{red,green,blue} LUT with derived loop index",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
