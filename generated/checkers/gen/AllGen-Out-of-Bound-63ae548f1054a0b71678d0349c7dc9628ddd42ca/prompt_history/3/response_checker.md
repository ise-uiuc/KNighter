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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary.

namespace {

class SAGenTestChecker : public Checker<check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Transfer-function LUT index out-of-bounds", "Array bounds")) {}

      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:
      // Return true if Base is of the form "...->tf_pts.red" (or green/blue), and
      // ArrTy is the constant array type of the color channel.
      bool isTFLutColorArray(const Expr *Base,
                             StringRef &ColorOut,
                             const ConstantArrayType *&ArrTy) const;

      // Extract index info: either a constant APSInt or a SymbolRef.
      void getIndexInfo(const Expr *Idx, CheckerContext &C, bool &IsConst,
                        llvm::APSInt &ConstVal, SymbolRef &Sym) const;

      // Best-effort suppression if a nearby condition guards "idx < TRANSFER_FUNC_POINTS".
      bool guardedByTransferPointsCondition(const Expr *Idx,
                                            const Stmt *AccessSite,
                                            CheckerContext &C) const;

      void reportOOB(const ArraySubscriptExpr *AE, StringRef ColorName,
                     CheckerContext &C) const;
};

bool SAGenTestChecker::isTFLutColorArray(const Expr *Base,
                                         StringRef &ColorOut,
                                         const ConstantArrayType *&ArrTy) const {
  if (!Base)
    return false;

  Base = Base->IgnoreParenImpCasts();
  const auto *ME1 = dyn_cast<MemberExpr>(Base);
  if (!ME1)
    return false;

  const auto *FD1 = dyn_cast<FieldDecl>(ME1->getMemberDecl());
  if (!FD1)
    return false;

  StringRef Color = FD1->getName();
  if (!(Color == "red" || Color == "green" || Color == "blue"))
    return false;

  const Expr *ME1BaseExpr = ME1->getBase();
  if (!ME1BaseExpr)
    return false;

  ME1BaseExpr = ME1BaseExpr->IgnoreParenImpCasts();
  const auto *ME2 = dyn_cast<MemberExpr>(ME1BaseExpr);
  if (!ME2)
    return false;

  const auto *FD2 = dyn_cast<FieldDecl>(ME2->getMemberDecl());
  if (!FD2)
    return false;

  if (FD2->getName() != "tf_pts")
    return false;

  // Get red/green/blue array type bound.
  QualType QT = FD1->getType();
  const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr());
  if (!CAT)
    return false;

  ColorOut = Color;
  ArrTy = CAT;
  return true;
}

void SAGenTestChecker::getIndexInfo(const Expr *Idx, CheckerContext &C,
                                    bool &IsConst, llvm::APSInt &ConstVal,
                                    SymbolRef &Sym) const {
  IsConst = false;
  Sym = nullptr;
  if (!Idx)
    return;

  // Try to evaluate as constant.
  if (EvaluateExprToInt(ConstVal, Idx, C)) {
    IsConst = true;
    return;
  }

  // Otherwise, try to obtain a symbol for the index.
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(Idx, C.getLocationContext());
  Sym = SV.getAsSymbol();
}

bool SAGenTestChecker::guardedByTransferPointsCondition(const Expr *Idx,
                                                        const Stmt *AccessSite,
                                                        CheckerContext &C) const {
  // We look for If/For/While/Do conditions that mention both the index name
  // and TRANSFER_FUNC_POINTS.
  const DeclRefExpr *IdxDRE = dyn_cast<DeclRefExpr>(Idx->IgnoreParenImpCasts());
  if (!IdxDRE)
    return false;

  const auto *VD = dyn_cast<VarDecl>(IdxDRE->getDecl());
  if (!VD)
    return false;

  StringRef IdxName = VD->getName();

  // Check an enclosing if
  if (const IfStmt *IS = findSpecificTypeInParents<IfStmt>(AccessSite, C)) {
    if (const Expr *CondE = IS->getCond()) {
      if (ExprHasName(CondE, IdxName, C) && ExprHasName(CondE, "TRANSFER_FUNC_POINTS", C))
        return true;
    }
  }
  // Check an enclosing for
  if (const ForStmt *FS = findSpecificTypeInParents<ForStmt>(AccessSite, C)) {
    if (const Expr *CondE = FS->getCond()) {
      if (ExprHasName(CondE, IdxName, C) && ExprHasName(CondE, "TRANSFER_FUNC_POINTS", C))
        return true;
    }
  }
  // Check an enclosing while
  if (const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(AccessSite, C)) {
    if (const Expr *CondE = WS->getCond()) {
      if (ExprHasName(CondE, IdxName, C) && ExprHasName(CondE, "TRANSFER_FUNC_POINTS", C))
        return true;
    }
  }
  // Check an enclosing do-while
  if (const DoStmt *DS = findSpecificTypeInParents<DoStmt>(AccessSite, C)) {
    if (const Expr *CondE = DS->getCond()) {
      if (ExprHasName(CondE, IdxName, C) && ExprHasName(CondE, "TRANSFER_FUNC_POINTS", C))
        return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportOOB(const ArraySubscriptExpr *AE, StringRef ColorName,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "Possible out-of-bounds read from tf_pts.";
  Msg += ColorName;
  Msg += "; missing index < TRANSFER_FUNC_POINTS check";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (AE)
    R->addRange(AE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad || !S)
    return;

  const auto *AE = dyn_cast<ArraySubscriptExpr>(S);
  if (!AE)
    return;

  const Expr *Base = AE->getBase();
  StringRef ColorName;
  const ConstantArrayType *ArrTy = nullptr;

  if (!isTFLutColorArray(Base, ColorName, ArrTy))
    return;

  // Get the array bound (TRANSFER_FUNC_POINTS after preprocessing).
  llvm::APInt ArrSize = ArrTy->getSize();

  // Analyze the index.
  const Expr *IdxE = AE->getIdx();
  if (!IdxE)
    return;

  bool IsConst = false;
  llvm::APSInt ConstVal;
  SymbolRef Sym = nullptr;
  getIndexInfo(IdxE, C, IsConst, ConstVal, Sym);

  // If constant index: report if negative or >= bound.
  if (IsConst) {
    // Negative index is OOB.
    if (ConstVal.isSigned() && ConstVal.isNegative()) {
      reportOOB(AE, ColorName, C);
      return;
    }
    // Compare against bound using consistent bitwidth/signedness.
    llvm::APSInt BoundAPS(ArrSize.zextOrTrunc(ConstVal.getBitWidth()),
                          ConstVal.isUnsigned());
    if (ConstVal >= BoundAPS) {
      reportOOB(AE, ColorName, C);
    }
    return;
  }

  // If symbolic index: try to prove safe using max value.
  if (Sym) {
    const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C);
    if (MaxV) {
      llvm::APSInt BoundAPS(ArrSize.zextOrTrunc(MaxV->getBitWidth()),
                            MaxV->isUnsigned());
      // If we can prove max < bound, it's safe.
      if (MaxV->ult(BoundAPS))
        return;
      // Otherwise, continue to optional guard check and potentially report.
    }
  }

  // Optional guard suppression: look for condition mentioning index and TRANSFER_FUNC_POINTS.
  if (guardedByTransferPointsCondition(IdxE, S, C))
    return;

  // Not proven safe and not guarded; report.
  reportOOB(AE, ColorName, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing bounds checks when indexing tf_pts.{red,green,blue} arrays (TRANSFER_FUNC_POINTS)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
