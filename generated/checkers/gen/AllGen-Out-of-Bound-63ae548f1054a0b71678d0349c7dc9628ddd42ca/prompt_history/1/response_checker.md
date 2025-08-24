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
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Out-of-bounds LUT access", "Array bounds")) {}

      void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

   private:
      bool isTfPtsColorArrayAccess(const ArraySubscriptExpr *ASE,
                                   const MemberExpr *&ColorME,
                                   llvm::APInt &ArraySize,
                                   CheckerContext &C) const;

      bool inLoop(const Stmt *S, CheckerContext &C) const;

      void reportOOB(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

bool SAGenTestChecker::inLoop(const Stmt *S, CheckerContext &C) const {
  if (findSpecificTypeInParents<ForStmt>(S, C))
    return true;
  if (findSpecificTypeInParents<WhileStmt>(S, C))
    return true;
  if (findSpecificTypeInParents<DoStmt>(S, C))
    return true;
  return false;
}

bool SAGenTestChecker::isTfPtsColorArrayAccess(const ArraySubscriptExpr *ASE,
                                               const MemberExpr *&ColorME,
                                               llvm::APInt &ArraySize,
                                               CheckerContext &C) const {
  if (!ASE)
    return false;

  const Expr *BaseE = ASE->getBase();
  if (!BaseE)
    return false;

  BaseE = BaseE->IgnoreParenImpCasts();

  const auto *MEColor = dyn_cast<MemberExpr>(BaseE);
  if (!MEColor)
    return false;

  const ValueDecl *VD = MEColor->getMemberDecl();
  if (!VD)
    return false;

  const auto *FD = dyn_cast<FieldDecl>(VD);
  if (!FD)
    return false;

  // Check color field name is one of red/green/blue
  StringRef FieldName = FD->getName();
  if (!(FieldName.equals("red") || FieldName.equals("green") || FieldName.equals("blue")))
    return false;

  // Confirm the base contains "tf_pts" (e.g., output_tf->tf_pts.red)
  const Expr *TFPtsBase = MEColor->getBase();
  if (!TFPtsBase)
    return false;

  if (!ExprHasName(TFPtsBase, "tf_pts", C))
    return false;

  // Retrieve the compile-time bound for the color array
  QualType FT = FD->getType();
  const ConstantArrayType *CAT = C.getASTContext().getAsConstantArrayType(FT);
  if (!CAT)
    return false; // Can't determine bound, skip.

  ArraySize = CAT->getSize();
  ColorME = MEColor;
  return true;
}

void SAGenTestChecker::reportOOB(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Index may exceed LUT size in tf_pts.<color>[i]", N);
  R->addRange(ASE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  // 1) Match output_tf->tf_pts.{red|green|blue}[...]
  const MemberExpr *ColorME = nullptr;
  llvm::APInt ArrSize;
  if (!isTfPtsColorArrayAccess(ASE, ColorME, ArrSize, C))
    return;

  // 2) Only focus on loop-based indexing (pattern-specific)
  if (!inLoop(ASE, C))
    return;

  // 3) Analyze the index expression
  const Expr *IdxE = ASE->getIdx();
  if (!IdxE)
    return;

  // Try to evaluate constant index
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, IdxE, C)) {
    // If negative or >= size -> OOB
    bool IsNeg = EvalRes.isSigned() && EvalRes.isNegative();
    uint64_t IdxVal = EvalRes.isSigned() ? (uint64_t)EvalRes.getSExtValue()
                                         : EvalRes.getZExtValue();
    if (IsNeg || IdxVal >= ArrSize.getZExtValue()) {
      reportOOB(ASE, C);
    }
    return; // either reported or proven safe here
  }

  // Otherwise, rely on symbolic bounds
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(IdxE, C.getLocationContext());
  SymbolRef Sym = SV.getAsSymbol();

  if (!Sym) {
    // No symbolic info; cannot prove safe.
    reportOOB(ASE, C);
    return;
  }

  const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C);
  if (Max) {
    // If max < size, safe on this path; otherwise report
    uint64_t MaxVal = Max->isSigned() ? (uint64_t)Max->getSExtValue()
                                      : Max->getZExtValue();
    if (MaxVal < ArrSize.getZExtValue())
      return; // proven safe
    reportOOB(ASE, C);
    return;
  }

  // Unknown max, cannot prove safe -> report
  reportOOB(ASE, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing bounds validation when indexing tf_pts.{red,green,blue} LUTs in loops",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
