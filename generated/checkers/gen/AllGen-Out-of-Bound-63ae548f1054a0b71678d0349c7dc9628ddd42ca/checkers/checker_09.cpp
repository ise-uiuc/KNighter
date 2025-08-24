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
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Index may exceed LUT size", "Memory Error")) {}

      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      bool isTargetLUTBase(const Expr *Base, CheckerContext &C) const;
      bool getArrayBoundFromColorMember(const Expr *Base, CheckerContext &C, llvm::APInt &OutSize) const;
      void reportOOB(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

bool SAGenTestChecker::isTargetLUTBase(const Expr *Base, CheckerContext &C) const {
  if (!Base)
    return false;
  const Expr *E = Base->IgnoreParenImpCasts();
  // Heuristic and focused match:
  // Must contain "output_tf", "tf_pts" and one of "red", "green", or "blue"
  if (!ExprHasName(E, "output_tf", C))
    return false;
  if (!ExprHasName(E, "tf_pts", C))
    return false;
  if (!(ExprHasName(E, "red", C) || ExprHasName(E, "green", C) || ExprHasName(E, "blue", C)))
    return false;
  return true;
}

bool SAGenTestChecker::getArrayBoundFromColorMember(const Expr *Base, CheckerContext &C, llvm::APInt &OutSize) const {
  if (!Base)
    return false;

  // Find the MemberExpr that refers to the color array field: red/green/blue
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Base);
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD)
    return false;

  QualType QT = VD->getType();

  // Obtain the array type and ensure it's a ConstantArrayType
  const ArrayType *AT = C.getASTContext().getAsArrayType(QT);
  if (!AT)
    return false;

  const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(AT);
  if (!CAT)
    return false;

  OutSize = CAT->getSize();
  return true;
}

void SAGenTestChecker::reportOOB(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Index i may exceed TRANSFER_FUNC_POINTS when indexing transfer-function LUT", N);
  if (ASE)
    R->addRange(ASE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkLocation(SVal /*Loc*/, bool /*IsLoad*/, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // We only care about array subscript expressions like output_tf->tf_pts.red[i]
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(S);
  if (!ASE)
    return;

  const Expr *BaseE = ASE->getBase();
  if (!BaseE)
    return;
  if (!isTargetLUTBase(BaseE, C))
    return;

  const Expr *IdxE = ASE->getIdx();
  if (!IdxE)
    return;
  IdxE = IdxE->IgnoreParenImpCasts();

  // Ensure the index is the loop variable "i" per target pattern
  if (!ExprHasName(IdxE, "i", C))
    return;

  // Get the bound from the color member array type (TRANSFER_FUNC_POINTS)
  llvm::APInt ArraySize;
  if (!getArrayBoundFromColorMember(BaseE, C, ArraySize))
    return; // Can't determine size, don't warn

  // If index is a constant, evaluate directly
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, IdxE, C)) {
    uint64_t IndexVal = EvalRes.getZExtValue();
    uint64_t Bound = ArraySize.getZExtValue();
    if (IndexVal >= Bound) {
      reportOOB(ASE, C);
    }
    return;
  }

  // Otherwise, try to infer a max bound for the symbolic index
  ProgramStateRef State = C.getState();
  SVal IdxSV = State->getSVal(IdxE, C.getLocationContext());
  SymbolRef Sym = IdxSV.getAsSymbol();
  if (!Sym) {
    // Not a simple symbol nor constant; we cannot prove safety, but refrain from noisy reporting
    return;
  }

  const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C);
  if (!Max) {
    // No upper bound known on this path -> potential OOB
    reportOOB(ASE, C);
    return;
  }

  uint64_t MaxVal = Max->getZExtValue();
  uint64_t BoundMinus1 = (ArraySize.getZExtValue() == 0) ? 0 : (ArraySize.getZExtValue() - 1);
  if (MaxVal > BoundMinus1) {
    reportOOB(ASE, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds indexing into output_tf->tf_pts.{red,green,blue}[i] without bound check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
