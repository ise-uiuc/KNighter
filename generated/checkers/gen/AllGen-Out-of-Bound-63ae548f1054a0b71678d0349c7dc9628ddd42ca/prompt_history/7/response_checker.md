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
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states required.

namespace {

class SAGenTestChecker : public Checker<check::Location> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds LUT access", "Array bounds")) {}

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  // Helper: get the ArraySubscriptExpr related to S, either S itself or a child.
  const ArraySubscriptExpr *getASEFromStmt(const Stmt *S, CheckerContext &C) const {
    if (!S)
      return nullptr;
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S))
      return ASE;
    return findSpecificTypeInChildren<ArraySubscriptExpr>(S);
  }

  // Helper: determine if the array base expression textually contains "tf_pts".
  bool isTFPLUTBase(const Expr *Base, CheckerContext &C) const {
    if (!Base)
      return false;
    return ExprHasName(Base, "tf_pts", C);
  }

  // Helper: extract constant array bound from a member expression base.
  bool getArrayBoundFromBaseExpr(const Expr *Base, CheckerContext &C,
                                 llvm::APInt &OutBound) const {
    if (!Base)
      return false;
    const Expr *E = Base->IgnoreImpCasts();
    // Expecting a MemberExpr chain leading to the array field (e.g., ...tf_pts.red)
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME)
      return false;

    QualType MTy = ME->getType();
    const ConstantArrayType *CAT =
        C.getASTContext().getAsConstantArrayType(MTy);
    if (!CAT)
      return false;

    OutBound = CAT->getSize();
    return true;
  }

  // Helper: find a DeclRefExpr within Idx and return its name if possible.
  bool getIndexVarName(const Expr *Idx, std::string &OutName) const {
    if (!Idx)
      return false;
    const Expr *I = Idx->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(I)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        OutName = VD->getName().str();
        return true;
      }
    }
    if (const auto *InnerDRE = findSpecificTypeInChildren<DeclRefExpr>(Idx)) {
      if (const auto *VD = dyn_cast<VarDecl>(InnerDRE->getDecl())) {
        OutName = VD->getName().str();
        return true;
      }
    }
    return false;
  }

  // Helper: does Cond mention both the index variable and TRANSFER_FUNC_POINTS?
  bool condMentionsIndexAndTFP(const Expr *Cond, StringRef IdxName,
                               CheckerContext &C) const {
    if (!Cond || IdxName.empty())
      return false;
    bool HasIdx = ExprHasName(Cond, IdxName, C);
    bool HasTFP = ExprHasName(Cond, "TRANSFER_FUNC_POINTS", C);
    return HasIdx && HasTFP;
  }

  // Helper: check if there is a nearby guard (if/loop condition) constraining index vs TRANSFER_FUNC_POINTS.
  bool isGuardedByTFP(const Expr *Idx, const Stmt *AccessSite,
                      CheckerContext &C) const {
    std::string IdxName;
    if (!getIndexVarName(Idx, IdxName))
      return false;

    // Check nearest enclosing if-statement.
    if (const IfStmt *IS = findSpecificTypeInParents<IfStmt>(AccessSite, C)) {
      if (condMentionsIndexAndTFP(IS->getCond(), IdxName, C))
        return true;
    }

    // Check nearest enclosing for/while/do conditions.
    if (const ForStmt *FS = findSpecificTypeInParents<ForStmt>(AccessSite, C)) {
      if (condMentionsIndexAndTFP(FS->getCond(), IdxName, C))
        return true;
    }
    if (const WhileStmt *WS =
            findSpecificTypeInParents<WhileStmt>(AccessSite, C)) {
      if (condMentionsIndexAndTFP(WS->getCond(), IdxName, C))
        return true;
    }
    if (const DoStmt *DS = findSpecificTypeInParents<DoStmt>(AccessSite, C)) {
      if (condMentionsIndexAndTFP(DS->getCond(), IdxName, C))
        return true;
    }

    return false;
  }

  // Helper: ensure we’re in a for-loop that iterates the same index var (to match the target pattern).
  bool isWithinForOverIndex(const Expr *Idx, const Stmt *AccessSite,
                            CheckerContext &C) const {
    std::string IdxName;
    if (!getIndexVarName(Idx, IdxName))
      return false;
    const ForStmt *FS = findSpecificTypeInParents<ForStmt>(AccessSite, C);
    if (!FS)
      return false;
    const Expr *Inc = FS->getInc();
    const Expr *Cond = FS->getCond();
    bool MentionsIdx =
        (Inc && ExprHasName(Inc, IdxName, C)) || (Cond && ExprHasName(Cond, IdxName, C));
    return MentionsIdx;
  }
};

void SAGenTestChecker::checkLocation(SVal /*Loc*/, bool /*IsLoad*/,
                                     const Stmt *S, CheckerContext &C) const {
  // Step A: focus on array subscript accesses.
  const auto *ASE = getASEFromStmt(S, C);
  if (!ASE)
    return;

  const Expr *Base = ASE->getBase();
  const Expr *Idx = ASE->getIdx();
  if (!Base || !Idx)
    return;

  // Heuristic: only consider LUT arrays under tf_pts.*
  if (!isTFPLUTBase(Base, C))
    return;

  // Get array bound (constant-size array only).
  llvm::APInt ArrayBound;
  if (!getArrayBoundFromBaseExpr(Base, C, ArrayBound))
    return;

  // Evaluate index: constant first.
  llvm::APSInt IdxVal;
  if (EvaluateExprToInt(IdxVal, Idx, C)) {
    // Definite check: negative or >= bound is OOB.
    bool IsNeg = IdxVal.isSigned() ? IdxVal.isNegative() : false;
    uint64_t UVal = IdxVal.getZExtValue();
    uint64_t Bound = ArrayBound.getZExtValue();
    if (IsNeg || UVal >= Bound) {
      // If explicitly guarded nearby, suppress.
      if (isGuardedByTFP(Idx, S, C))
        return;

      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "Possible out-of-bounds LUT access: index may exceed array size",
          N);
      R->addRange(ASE->getSourceRange());
      C.emitReport(std::move(R));
    }
    return; // Constant and in-bounds => safe.
  }

  // Symbolic index: ask the constraint manager for a maximum value.
  ProgramStateRef State = C.getState();
  SVal IdxSVal = State->getSVal(Idx, C.getLocationContext());
  SymbolRef IdxSym = IdxSVal.getAsSymbol();
  if (!IdxSym)
    return; // Unknown index; avoid noise.

  const llvm::APSInt *MaxVal = inferSymbolMaxVal(IdxSym, C);
  uint64_t Bound = ArrayBound.getZExtValue();

  // If proven safe (max < bound), return.
  if (MaxVal && MaxVal->getZExtValue() < Bound)
    return;

  // Require that we are inside a for-loop iterating the index var to match the target pattern.
  if (!isWithinForOverIndex(Idx, S, C))
    return;

  // Suppress if there’s an explicit guard against TRANSFER_FUNC_POINTS nearby.
  if (isGuardedByTFP(Idx, S, C))
    return;

  // Potentially unsafe: emit a warning.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Possible out-of-bounds LUT access: index is not checked against TRANSFER_FUNC_POINTS",
      N);
  R->addRange(ASE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing upper-bound checks when indexing fixed-size LUT arrays (TRANSFER_FUNC_POINTS)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
