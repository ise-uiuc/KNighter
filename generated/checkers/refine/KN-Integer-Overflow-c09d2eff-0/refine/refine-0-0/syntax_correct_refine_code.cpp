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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the user context.
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<BinaryOperator>> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "32-bit multiply widened to 64-bit",
                       "Integer Overflow")) {}

  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;

private:
  // Helpers
  static unsigned getIntWidth(QualType T, CheckerContext &C) {
    return C.getASTContext().getIntWidth(T);
  }

  static bool isInt64OrWider(QualType T, CheckerContext &C) {
    return T->isIntegerType() && getIntWidth(T, C) >= 64;
  }

  static bool isIntegerType(const Expr *E) {
    if (!E) return false;
    return E->getType()->isIntegerType();
  }

  static const Expr *ignorePII(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  // Determine if E is immediately used as the RHS of an assignment to a 64-bit int.
  bool isImmediateRHSOfAssignTo64(const Expr *E, CheckerContext &C) const {
    const auto *ParentBO = findSpecificTypeInParents<BinaryOperator>(E, C);
    if (!ParentBO || !ParentBO->isAssignmentOp())
      return false;

    const Expr *RHS = ParentBO->getRHS();
    if (!RHS)
      return false;

    // Ensure E is exactly the RHS (ignoring parens/implicit casts).
    if (ignorePII(RHS) != ignorePII(E))
      return false;

    const Expr *LHS = ParentBO->getLHS();
    return LHS && isInt64OrWider(LHS->getType(), C);
  }

  // Determine if E is the initializer of a 64-bit variable.
  bool isInitializerOf64Var(const Expr *E, CheckerContext &C) const {
    const auto *DS = findSpecificTypeInParents<DeclStmt>(E, C);
    if (!DS)
      return false;

    const Expr *ECore = ignorePII(E);

    for (const Decl *D : DS->decls()) {
      const auto *VD = dyn_cast<VarDecl>(D);
      if (!VD || !VD->hasInit())
        continue;
      if (!isInt64OrWider(VD->getType(), C))
        continue;
      const Expr *Init = VD->getInit();
      if (ignorePII(Init) == ECore)
        return true;
    }
    return false;
  }

  // Determine if E is the returned expression of a function returning 64-bit.
  bool isImmediateReturnOf64(const Expr *E, CheckerContext &C) const {
    const auto *RS = findSpecificTypeInParents<ReturnStmt>(E, C);
    if (!RS)
      return false;
    const Expr *Ret = RS->getRetValue();
    if (!Ret || ignorePII(Ret) != ignorePII(E))
      return false;

    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!D)
      return false;
    return isInt64OrWider(D->getReturnType(), C);
  }

  // Determine if E is passed as an argument to a 64-bit parameter.
  bool isPassedTo64Param(const Expr *E, CheckerContext &C) const {
    const auto *Call = findSpecificTypeInParents<CallExpr>(E, C);
    if (!Call)
      return false;

    const FunctionDecl *FD = Call->getDirectCallee();
    if (!FD)
      return false;

    const Expr *ECore = ignorePII(E);
    for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
      const Expr *Arg = Call->getArg(i);
      if (!Arg)
        continue;
      if (ignorePII(Arg) == ECore) {
        QualType ParamTy = FD->getParamDecl(i)->getType();
        if (isInt64OrWider(ParamTy, C))
          return true;
      }
    }
    return false;
  }

  // Determine if E is explicitly cast to 64-bit using a C-style cast.
  bool isExplicitlyCastTo64(const Expr *E, CheckerContext &C) const {
    const auto *CS = findSpecificTypeInParents<CStyleCastExpr>(E, C);
    if (!CS)
      return false;
    if (ignorePII(CS->getSubExpr()) != ignorePII(E))
      return false;

    QualType DestTy = CS->getTypeAsWritten();
    return isInt64OrWider(DestTy, C);
  }

  // The only contexts we want to consider as "widened to 64" to avoid FPs:
  bool isRelevantWidenedUseTo64(const Expr *E, CheckerContext &C) const {
    return isImmediateRHSOfAssignTo64(E, C) ||
           isInitializerOf64Var(E, C) ||
           isImmediateReturnOf64(E, C) ||
           isPassedTo64Param(E, C) ||
           isExplicitlyCastTo64(E, C);
  }

  // Try to get the maximum possible value of an expression.
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    // Try constant evaluation
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Try symbolic max value
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (!Sym)
      return false;

    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
      Out = *MaxV;
      return true;
    }
    return false;
  }

  // Check if we can prove the product fits into the narrow type; if yes, suppress.
  bool productDefinitelyFits(const BinaryOperator *B, CheckerContext &C) const {
    if (!B) return false;
    const Expr *LHS = B->getLHS();
    const Expr *RHS = B->getRHS();
    if (!LHS || !RHS)
      return false;

    llvm::APSInt MaxL, MaxR;
    if (!getMaxForExpr(LHS, C, MaxL) || !getMaxForExpr(RHS, C, MaxR))
      return false; // Can't prove, so not definitely safe.

    // Compute product with 128-bit headroom using unsigned math.
    uint64_t ML = MaxL.getZExtValue();
    uint64_t MR = MaxR.getZExtValue();
    __uint128_t Prod = ( (__uint128_t)ML ) * ( (__uint128_t)MR );

    // Determine limit for the narrow type (result type of the multiply).
    unsigned MulW = getIntWidth(B->getType(), C);
    bool IsUnsigned = B->getType()->isUnsignedIntegerType();
    __uint128_t Limit;
    if (IsUnsigned) {
      if (MulW >= 64) {
        // If multiply is already 64-bit or more, treat as safe.
        return true;
      }
      Limit = (((__uint128_t)1) << MulW) - 1;
    } else {
      if (MulW == 0)
        return false;
      if (MulW >= 64) {
        // As above, treat as safe (won't reach in typical flow).
        return true;
      }
      // Signed max: 2^(W-1) - 1
      Limit = (((__uint128_t)1) << (MulW - 1)) - 1;
    }

    return Prod <= Limit;
  }
};

void SAGenTestChecker::checkPostStmt(const BinaryOperator *B, CheckerContext &C) const {
  if (!B)
    return;

  // Only care about integer multiplication.
  if (B->getOpcode() != BO_Mul)
    return;
  if (!B->getType()->isIntegerType())
    return;

  // The multiply's arithmetic width (after integer promotions).
  unsigned MulWidth = getIntWidth(B->getType(), C);

  // If arithmetic is already 64-bit or more, that's OK.
  if (MulWidth >= 64)
    return;

  // Ensure operands are integer-typed as well.
  if (!isIntegerType(B->getLHS()) || !isIntegerType(B->getRHS()))
    return;

  const Expr *E = dyn_cast<Expr>(B);
  if (!E)
    return;

  // Only warn when the 32-bit multiply result is materialized in a 64-bit context
  // that matches the bug pattern: assignment/initialization, return, param passing,
  // or explicit cast. Do NOT warn for promotions due to other arithmetic ops
  // (e.g., division with a 64-bit numerator), which caused the FP.
  if (!isRelevantWidenedUseTo64(E, C))
    return;

  // Optional reduction: if we can prove product fits in the narrow type, don't warn.
  if (productDefinitelyFits(B, C))
    return;

  // Report: multiplication in 32-bit (or narrower) that is widened to 64-bit
  // only at the use site, risking overflow before the widening.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply",
      N);
  R->addRange(B->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect 32-bit multiply whose result is only widened to 64-bit afterward, risking overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
