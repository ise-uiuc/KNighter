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
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::Location> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "LUT index out of bounds", "Array Bounds")) {}

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  bool getArrayBoundFromBaseExpr(const Expr *BaseE, llvm::APInt &N, CheckerContext &C) const;
  bool extractStrictUpperBoundFromCond(const Expr *CondE, SymbolRef IdxSym,
                                       llvm::APSInt &StrictUB, CheckerContext &C) const;
  bool hasSyntacticUpperBoundGuard(const Stmt *S, const Expr *IdxE,
                                   const llvm::APInt &N, CheckerContext &C) const;
  bool shouldReportForBase(const Expr *BaseE) const;
};

// Get constant array size from various base expressions (DeclRefExpr or MemberExpr)
bool SAGenTestChecker::getArrayBoundFromBaseExpr(const Expr *BaseE, llvm::APInt &N, CheckerContext &C) const {
  if (!BaseE)
    return false;

  // Try DeclRefExpr array
  if (getArraySizeFromExpr(N, BaseE))
    return true;

  // Try MemberExpr to a field that's a constant array
  if (const auto *ME = dyn_cast<MemberExpr>(BaseE->IgnoreParenImpCasts())) {
    const ValueDecl *VD = ME->getMemberDecl();
    if (!VD)
      return false;

    QualType QT = VD->getType();
    if (const auto *CAT = dyn_cast_or_null<ConstantArrayType>(C.getASTContext().getAsArrayType(QT))) {
      N = CAT->getSize();
      return true;
    }
    if (const ConstantArrayType *CAT2 = C.getASTContext().getAsConstantArrayType(QT)) {
      N = CAT2->getSize();
      return true;
    }
  }

  // As a fallback, attempt from the expression's QualType (e.g., base ME type)
  QualType BQT = BaseE->getType();
  if (const ConstantArrayType *CAT3 = C.getASTContext().getAsConstantArrayType(BQT)) {
    N = CAT3->getSize();
    return true;
  }

  return false;
}

// Try to get a strict upper bound (exclusive) for IdxSym from a loop/while condition.
// Returns true and sets StrictUB iff condition is of form:
//   idx < C   => UB = C
//   idx <= C  => UB = C + 1
//   C > idx   => UB = C
//   C >= idx  => UB = C + 1
bool SAGenTestChecker::extractStrictUpperBoundFromCond(const Expr *CondE, SymbolRef IdxSym,
                                                       llvm::APSInt &StrictUB, CheckerContext &C) const {
  if (!CondE || !IdxSym)
    return false;

  const Expr *E = CondE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (!(Op == BO_LT || Op == BO_LE || Op == BO_GT || Op == BO_GE))
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  ProgramStateRef State = C.getState();
  SymbolRef LHSSym = State->getSVal(LHS, C.getLocationContext()).getAsSymbol();
  SymbolRef RHSSym = State->getSVal(RHS, C.getLocationContext()).getAsSymbol();

  llvm::APSInt ConstVal;

  // Case 1: idx [<|<=] C
  if (LHSSym && LHSSym == IdxSym) {
    if (!EvaluateExprToInt(ConstVal, RHS, C))
      return false;
    if (Op == BO_LT) {
      StrictUB = ConstVal;
      return true;
    } else if (Op == BO_LE) {
      // UB = C + 1
      StrictUB = ConstVal;
      StrictUB = StrictUB + 1;
      return true;
    }
  }

  // Case 2: C [>|>=] idx
  if (RHSSym && RHSSym == IdxSym) {
    if (!EvaluateExprToInt(ConstVal, LHS, C))
      return false;
    if (Op == BO_GT) {
      StrictUB = ConstVal;
      return true;
    } else if (Op == BO_GE) {
      StrictUB = ConstVal;
      StrictUB = StrictUB + 1;
      return true;
    }
  }

  return false;
}

// Check for enclosing loop guard that provides a constant strict UB for the same index.
// If such UB exists and UB <= N, we treat it as adequately guarded.
bool SAGenTestChecker::hasSyntacticUpperBoundGuard(const Stmt *S, const Expr *IdxE,
                                                   const llvm::APInt &N, CheckerContext &C) const {
  if (!S || !IdxE)
    return false;

  ProgramStateRef State = C.getState();
  SymbolRef IdxSym = State->getSVal(IdxE, C.getLocationContext()).getAsSymbol();
  if (!IdxSym)
    return false;

  // Check enclosing ForStmt
  if (const ForStmt *FS = findSpecificTypeInParents<ForStmt>(S, C)) {
    const Expr *Cond = FS->getCond();
    llvm::APSInt UB;
    if (extractStrictUpperBoundFromCond(Cond, IdxSym, UB, C)) {
      uint64_t UBv = UB.isSigned() ? UB.extOrTrunc(64).getZExtValue() : UB.getZExtValue();
      uint64_t Nv = N.getLimitedValue();
      if (UBv <= Nv)
        return true;
    }
  }

  // Check enclosing WhileStmt
  if (const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(S, C)) {
    const Expr *Cond = WS->getCond();
    llvm::APSInt UB;
    if (extractStrictUpperBoundFromCond(Cond, IdxSym, UB, C)) {
      uint64_t UBv = UB.isSigned() ? UB.extOrTrunc(64).getZExtValue() : UB.getZExtValue();
      uint64_t Nv = N.getLimitedValue();
      if (UBv <= Nv)
        return true;
    }
  }

  return false;
}

// To reduce duplicates for rgb channels, only report for "red" when the base is a member named red.
// For other arrays (non-rgb), report normally.
bool SAGenTestChecker::shouldReportForBase(const Expr *BaseE) const {
  if (!BaseE)
    return true;

  if (const auto *ME = dyn_cast<MemberExpr>(BaseE->IgnoreParenImpCasts())) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      StringRef Name = FD->getName();
      if (Name == "red")
        return true;
      if (Name == "green" || Name == "blue")
        return false; // suppress duplicates; "red" will represent the issue
    }
  }
  return true;
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!IsLoad || !S)
    return;

  // Find the array subscript involved in this memory access.
  const ArraySubscriptExpr *ASE = nullptr;
  if ((ASE = dyn_cast<ArraySubscriptExpr>(S)) == nullptr) {
    ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S);
  }
  if (!ASE)
    return;

  const Expr *BaseE = ASE->getBase()->IgnoreParenImpCasts();
  const Expr *IdxE = ASE->getIdx()->IgnoreParenImpCasts();
  if (!BaseE || !IdxE)
    return;

  if (!shouldReportForBase(BaseE))
    return;

  // Get array bound N
  llvm::APInt N(32, 0);
  if (!getArrayBoundFromBaseExpr(BaseE, N, C))
    return; // Unknown bound -> avoid false positives

  // Evaluate index constant if possible
  llvm::APSInt IdxConst;
  if (EvaluateExprToInt(IdxConst, IdxE, C)) {
    // Treat negative or >= N as OOB
    bool IsNeg = IdxConst.isSigned() ? IdxConst.isNegative() : false;
    uint64_t IdxVal = IdxConst.isSigned() ? IdxConst.extOrTrunc(64).getZExtValue()
                                          : IdxConst.getZExtValue();
    uint64_t Bound = N.getLimitedValue();
    if (IsNeg || IdxVal >= Bound) {
      ExplodedNode *NNode = C.generateNonFatalErrorNode();
      if (!NNode)
        return;
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "Possible out-of-bounds LUT index; missing 'i < array_size' check.", NNode);
      R->addRange(IdxE->getSourceRange());
      C.emitReport(std::move(R));
    }
    return; // Constant and in-bounds otherwise: safe
  }

  // Non-constant index: use symbolic reasoning
  ProgramStateRef State = C.getState();
  SymbolRef IdxSym = State->getSVal(IdxE, C.getLocationContext()).getAsSymbol();
  if (!IdxSym)
    return; // Can't reason: avoid FP

  const llvm::APSInt *MaxV = inferSymbolMaxVal(IdxSym, C);
  if (MaxV) {
    // If analyzer can prove max < N, it's safe
    uint64_t MaxVal = MaxV->isSigned() ? MaxV->extOrTrunc(64).getZExtValue() : MaxV->getZExtValue();
    uint64_t Bound = N.getLimitedValue();
    if (MaxVal < Bound)
      return;
    // Otherwise, try to find a syntactic guard
    if (hasSyntacticUpperBoundGuard(S, IdxE, N, C))
      return;
  } else {
    // Unknown max bound; check for syntactic guard
    if (hasSyntacticUpperBoundGuard(S, IdxE, N, C))
      return;
  }

  // Report potential out-of-bounds index due to missing explicit check
  ExplodedNode *NNode = C.generateNonFatalErrorNode();
  if (!NNode)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible out-of-bounds LUT index; missing 'i < array_size' check.", NNode);
  R->addRange(IdxE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing upper-bound checks for LUT indices leading to out-of-bounds access",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
