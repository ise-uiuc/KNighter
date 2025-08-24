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
#include "clang/AST/ExprCXX.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the user prompt (assumed available)
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool functionKnownToDeref(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>,
        check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow shift widened to 64-bit", "Integer")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                   CheckerContext &C, StringRef Ctx) const;

  static const BinaryOperator *findShiftInTree(const Stmt *S);
  static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);

  // Helpers to refine and reduce false positives.
  static const Expr *peel(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static const BinaryOperator *asShift(const Stmt *S) {
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Shl)
        return BO;
    }
    return nullptr;
  }

  // Report only if the shift is the top-level expression reaching the 64-bit destination.
  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  // Precise constant-safety check: if both LHS and RHS are constant and the result
  // provably fits into the LHS bitwidth, we suppress.
  static bool constantShiftFitsInLHSWidth(const Expr *L, const Expr *R,
                                          unsigned LHSW, CheckerContext &C) {
    llvm::APSInt LHSEval, RHSEval;
    if (!EvaluateExprToInt(LHSEval, L, C))
      return false;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;

    // Be conservative for negative LHS.
    if (LHSEval.isSigned() && LHSEval.isNegative())
      return false;

    // Active bits of the non-negative LHS.
    unsigned LBits = LHSEval.getActiveBits(); // 0 if value == 0
    uint64_t ShiftAmt = RHSEval.getZExtValue();

    // Safe if highest set bit after shifting still fits in LHS width.
    // LBits == 0 is always safe (0 << n == 0).
    if (LBits == 0)
      return true;

    return (uint64_t)LBits + ShiftAmt <= (uint64_t)LHSW;
  }

  // Try to get an upper bound for the shift amount from constants or the constraint manager.
  static bool getUpperBoundForShiftAmount(const Expr *R, uint64_t &UB,
                                          CheckerContext &C) {
    if (!R)
      return false;

    llvm::APSInt RHSEval;
    if (EvaluateExprToInt(RHSEval, R, C)) {
      if (RHSEval.isSigned() && RHSEval.isNegative())
        return false;
      UB = RHSEval.getZExtValue();
      return true;
    }

    ProgramStateRef State = C.getState();
    SVal RV = State->getSVal(R, C.getLocationContext());
    if (SymbolRef Sym = RV.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        if (Max->isSigned() && Max->isNegative())
          return false;
        UB = Max->getZExtValue();
        return true;
      }
    }

    // As a small fallback, handle simple "X * Const" forms if we can bound X.
    if (const auto *BO = dyn_cast<BinaryOperator>(peel(R))) {
      if (BO->getOpcode() == BO_Mul) {
        // Try (X * C) or (C * X)
        llvm::APSInt ConstEval;
        const Expr *A = BO->getLHS();
        const Expr *B = BO->getRHS();

        const Expr *X = nullptr;
        uint64_t Factor = 0;

        if (EvaluateExprToInt(ConstEval, A, C)) {
          if (!(ConstEval.isSigned() && ConstEval.isNegative())) {
            Factor = ConstEval.getZExtValue();
            X = B;
          } else {
            return false;
          }
        } else if (EvaluateExprToInt(ConstEval, B, C)) {
          if (!(ConstEval.isSigned() && ConstEval.isNegative())) {
            Factor = ConstEval.getZExtValue();
            X = A;
          } else {
            return false;
          }
        }

        if (X && Factor != 0) {
          uint64_t XUB = 0;
          if (getUpperBoundForShiftAmount(X, XUB, C)) {
            // Beware of overflow; clamp to 64-bit.
            llvm::APInt Prod(128, XUB);
            Prod *= llvm::APInt(128, Factor);
            UB = Prod.getZExtValue();
            return true;
          }
        }
      }
    }

    return false;
  }

  // Try to get a safe upper bound on the number of active bits the left operand can have.
  // Returns true if it could compute a non-negative bound.
  static bool getMaxActiveBitsForLHS(const Expr *L, unsigned &ActiveBits,
                                     CheckerContext &C) {
    if (!L)
      return false;

    llvm::APSInt LHSEval;
    if (EvaluateExprToInt(LHSEval, L, C)) {
      if (LHSEval.isSigned() && LHSEval.isNegative())
        return false;
      ActiveBits = LHSEval.getActiveBits(); // 0 for 0
      return true;
    }

    ProgramStateRef State = C.getState();
    SVal LV = State->getSVal(L, C.getLocationContext());
    if (SymbolRef Sym = LV.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        if (Max->isSigned() && Max->isNegative())
          return false;
        ActiveBits = Max->getActiveBits();
        return true;
      }
    }

    return false;
  }

  // If we can prove that the 32-bit shift result fits entirely within the LHS bitwidth,
  // it is safe to perform the shift in 32-bit even if the overall destination is 64-bit.
  static bool shiftResultProvablyFitsInLHSType(const Expr *L, const Expr *R,
                                               unsigned LHSW, CheckerContext &C) {
    // Fast path for fully constant expressions.
    if (constantShiftFitsInLHSWidth(L, R, LHSW, C))
      return true;

    // Path-sensitive bound: get RHS upper bound and LHS max active bits.
    uint64_t ShiftUB = 0;
    unsigned LActiveBits = 0;
    if (!getUpperBoundForShiftAmount(R, ShiftUB, C))
      return false;
    if (!getMaxActiveBitsForLHS(L, LActiveBits, C))
      return false;

    // 0 << n is always safe
    if (LActiveBits == 0)
      return true;

    return (uint64_t)LActiveBits + ShiftUB <= (uint64_t)LHSW;
  }

  // Centralized FP gate for structural/context checks.
  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     CheckerContext &C) {
    // Suppress if the shift isn't the top-level expression being assigned/returned/passed.
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    (void)C; // currently unused, keep signature for future extensions
    return false;
  }
};

const BinaryOperator *SAGenTestChecker::findShiftInTree(const Stmt *S) {
  if (!S)
    return nullptr;

  if (const BinaryOperator *B = asShift(S))
    return B;

  for (const Stmt *Child : S->children()) {
    if (const BinaryOperator *Res = findShiftInTree(Child))
      return Res;
  }
  return nullptr;
}

bool SAGenTestChecker::hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx) {
  if (!E)
    return false;

  if (const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParens())) {
    QualType ToTy = ECE->getType();
    if (ToTy->isIntegerType() && ACtx.getIntWidth(ToTy) >= 64)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (!Child)
      continue;
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasExplicitCastToWide64(CE, ACtx))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                                   CheckerContext &C, StringRef) const {
  if (!E)
    return;

  ASTContext &ACtx = C.getASTContext();

  if (!DestTy->isIntegerType())
    return;

  unsigned DestW = ACtx.getIntWidth(DestTy);
  if (DestW < 64)
    return;

  const BinaryOperator *Shl = findShiftInTree(E);
  if (!Shl || Shl->getOpcode() != BO_Shl)
    return;

  const Expr *L = Shl->getLHS();
  const Expr *R = Shl->getRHS();
  if (!L || !R)
    return;

  QualType ShlTy = Shl->getType();
  if (!ShlTy->isIntegerType())
    return;

  unsigned ShlW = ACtx.getIntWidth(ShlTy);
  if (ShlW >= 64)
    return; // Shift already performed in 64-bit, OK.

  // LHS must be integer and narrower than 64.
  if (!L->getType()->isIntegerType())
    return;

  unsigned LHSW = ACtx.getIntWidth(L->getType());
  if (LHSW >= 64)
    return; // LHS is already wide enough.

  // If there is an explicit cast to >=64-bit within the LHS subtree, suppress.
  if (hasExplicitCastToWide64(L, ACtx))
    return;

  // Suppress known false-positive contexts.
  if (isFalsePositiveContext(E, Shl, C))
    return;

  // New: path-sensitive suppression. If we can prove the 32-bit shift result fits in LHS width,
  // then computing in 32-bit is safe, even if the destination is 64-bit.
  if (shiftResultProvablyFitsInLHSType(L, R, LHSW, C))
    return;

  // Report
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Shift done in 32-bit, widened after; cast left operand to 64-bit before <<", N);
  Rpt->addRange(Shl->getSourceRange());
  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->hasInit())
      continue;

    QualType DestTy = VD->getType();
    const Expr *Init = VD->getInit();
    analyzeAndReportShiftToWide(Init, DestTy, C, "initialization");
  }
}

void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  const StackFrameContext *SFC = C.getStackFrame();
  if (!SFC)
    return;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(SFC->getDecl());
  if (!FD)
    return;

  QualType DestTy = FD->getReturnType();
  analyzeAndReportShiftToWide(RetE, DestTy, C, "return");
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  unsigned NumArgs = Call.getNumArgs();
  unsigned NumParams = FD->getNumParams();
  unsigned N = std::min(NumArgs, NumParams);

  for (unsigned i = 0; i < N; ++i) {
    const ParmVarDecl *P = FD->getParamDecl(i);
    if (!P)
      continue;
    QualType DestTy = P->getType();
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    analyzeAndReportShiftToWide(ArgE, DestTy, C, "argument");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit left shift widened to 64-bit after the shift (cast should be before <<)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
