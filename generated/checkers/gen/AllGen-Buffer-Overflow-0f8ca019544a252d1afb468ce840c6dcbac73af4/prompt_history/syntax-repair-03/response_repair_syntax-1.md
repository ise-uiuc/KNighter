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
#include "clang/Lex/Lexer.h"
#include <string>
#include <sstream>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary.

namespace {

class SAGenTestChecker : public Checker<check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Index may exceed array size", "Buffer Overflow")) {}

      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helper: Try to obtain constant array size from the base expression of an array subscript.
      bool getConstantArraySizeFromBase(const Expr *Base, llvm::APInt &Size, CheckerContext &C) const;

      // Helper: Obtain a maximum possible value for an index expression along the current path.
      // KnownKind: 0 = exact constant; 1 = path-constrained max.
      bool getIndexMax(const Expr *IdxE, CheckerContext &C, llvm::APSInt &MaxIdx, unsigned &KnownKind) const;

      // Helper: If within a for-loop, extract a constant loop upper bound for the index variable.
      bool getLoopUpperBoundIfApplicable(const ArraySubscriptExpr *ASE, const Expr *IdxE,
                                         CheckerContext &C, llvm::APSInt &LoopMaxIdx) const;

      void report(const ArraySubscriptExpr *ASE, uint64_t ArrSize, uint64_t MaxIdxVal,
                  CheckerContext &C) const;
};

// Implementation

bool SAGenTestChecker::getConstantArraySizeFromBase(const Expr *Base, llvm::APInt &Size,
                                                    CheckerContext &C) const {
  if (!Base)
    return false;

  const Expr *E = Base;

  // If there is an ArrayToPointerDecay, strip it to reach the array-typed expr.
  if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
    if (ICE->getCastKind() == CK_ArrayToPointerDecay)
      E = ICE->getSubExpr();
  }

  // Try direct: if expression type is a constant array type.
  QualType QT = E->getType();
  if (!QT.isNull()) {
    if (const auto *CAT = dyn_cast_or_null<ConstantArrayType>(QT.getTypePtrOrNull())) {
      Size = CAT->getSize();
      return true;
    }
  }

  // Strip parens/casts after checking for decay, to find DeclRefExpr/MemberExpr.
  E = E->IgnoreParenCasts();

  // DeclRefExpr (global/local arrays)
  if (getArraySizeFromExpr(Size, E))
    return true;

  // MemberExpr (array field in struct/union)
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      QualType FT = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr())) {
        Size = CAT->getSize();
        return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::getIndexMax(const Expr *IdxE, CheckerContext &C,
                                   llvm::APSInt &MaxIdx, unsigned &KnownKind) const {
  if (!IdxE)
    return false;

  // First: try to evaluate as constant.
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, IdxE, C)) {
    MaxIdx = EvalRes;
    KnownKind = 0; // exact
    return true;
  }

  // Otherwise, try to obtain a symbol and infer maximal value along current path.
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(IdxE, C.getLocationContext());
  if (SymbolRef Sym = SV.getAsSymbol()) {
    if (const llvm::APSInt *maxVal = inferSymbolMaxVal(Sym, C)) {
      MaxIdx = *maxVal;
      KnownKind = 1; // path-constrained max
      return true;
    }
  }
  return false;
}

static const DeclRefExpr *getAsDeclRef(const Expr *E) {
  if (!E) return nullptr;
  return dyn_cast<DeclRefExpr>(E->IgnoreParenCasts());
}

bool SAGenTestChecker::getLoopUpperBoundIfApplicable(const ArraySubscriptExpr *ASE,
                                                     const Expr *IdxE,
                                                     CheckerContext &C,
                                                     llvm::APSInt &LoopMaxIdx) const {
  if (!ASE || !IdxE)
    return false;

  const DeclRefExpr *IdxDRE = getAsDeclRef(IdxE);
  if (!IdxDRE)
    return false;

  const auto *VD = dyn_cast<VarDecl>(IdxDRE->getDecl());
  if (!VD)
    return false;

  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(ASE, C);
  if (!FS)
    return false;

  const Expr *CondE = FS->getCond();
  if (!CondE)
    return false;

  const auto *CondBO = dyn_cast<BinaryOperator>(CondE->IgnoreParenCasts());
  if (!CondBO)
    return false;

  BinaryOperator::Opcode Opc = CondBO->getOpcode();
  if (Opc != BO_LT && Opc != BO_LE)
    return false;

  const Expr *LHS = CondBO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = CondBO->getRHS()->IgnoreParenCasts();

  const DeclRefExpr *LHSVar = getAsDeclRef(LHS);
  const DeclRefExpr *RHSVar = getAsDeclRef(RHS);

  const Expr *BoundExpr = nullptr;

  if (LHSVar && LHSVar->getDecl() == VD) {
    BoundExpr = RHS;
  } else if (RHSVar && RHSVar->getDecl() == VD) {
    BoundExpr = LHS;
  } else {
    return false;
  }

  llvm::APSInt UB;
  if (!EvaluateExprToInt(UB, BoundExpr, C))
    return false;

  // Convert to an appropriate index maximum (for i < UB, max is UB-1; for i <= UB, max is UB).
  if (Opc == BO_LT) {
    // UB - 1
    if (UB == 0) {
      // i < 0 is empty, but be conservative.
      LoopMaxIdx = UB;
    } else {
      LoopMaxIdx = UB - 1;
    }
  } else {
    LoopMaxIdx = UB;
  }

  return true;
}

void SAGenTestChecker::report(const ArraySubscriptExpr *ASE, uint64_t ArrSize,
                              uint64_t MaxIdxVal, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg = "Index may exceed array size (size=" + std::to_string(ArrSize) +
                    ", max=" + std::to_string(MaxIdxVal) + ")";
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);

  // Highlight the indexing expression.
  R->addRange(ASE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Try to find an ArraySubscriptExpr related to this memory access.
  const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S);
  if (!ASE)
    ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S);
  if (!ASE)
    return;

  // Get constant array size from the base expression (compile-time known arrays only).
  llvm::APInt ArraySizeAP;
  if (!getConstantArraySizeFromBase(ASE->getBase(), ArraySizeAP, C))
    return;

  uint64_t ArrSize = ArraySizeAP.getZExtValue();

  // Analyze the index expression to get a max bound.
  const Expr *IdxE = ASE->getIdx()->IgnoreParenImpCasts();

  llvm::APSInt MaxIdx;
  unsigned KnownKind = 2; // unknown
  if (getIndexMax(IdxE, C, MaxIdx, KnownKind)) {
    // Prepare a comparable APSInt for array size using MaxIdx's bitwidth/sign.
    llvm::APInt ArrSizeAsAPInt(MaxIdx.getBitWidth(), ArrSize);
    llvm::APSInt ArrSizeAPS(ArrSizeAsAPInt, MaxIdx.isUnsigned());

    if (MaxIdx >= ArrSizeAPS) {
      // Form a reasonable max value for message.
      uint64_t MaxIdxVal = MaxIdx.isUnsigned()
                               ? MaxIdx.getZExtValue()
                               : (MaxIdx.isNegative() ? 0ULL
                                                      : static_cast<uint64_t>(MaxIdx.getSExtValue()));
      report(ASE, ArrSize, MaxIdxVal, C);
    }
    return; // If we have path-constrained info, do not fallback to loop bound.
  }

  // Fallback: Extract loop upper bound if applicable (common pattern i < CONST).
  llvm::APSInt LoopMaxIdx;
  if (getLoopUpperBoundIfApplicable(ASE, IdxE, C, LoopMaxIdx)) {
    llvm::APInt ArrSizeAsAPInt(LoopMaxIdx.getBitWidth(), ArrSize);
    llvm::APSInt ArrSizeAPS(ArrSizeAsAPInt, LoopMaxIdx.isUnsigned());
    if (LoopMaxIdx >= ArrSizeAPS) {
      uint64_t MaxIdxVal = LoopMaxIdx.isUnsigned()
                               ? LoopMaxIdx.getZExtValue()
                               : (LoopMaxIdx.isNegative() ? 0ULL
                                                          : static_cast<uint64_t>(LoopMaxIdx.getSExtValue()));
      report(ASE, ArrSize, MaxIdxVal, C);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects array indexing where loop bound constant may exceed the array's compile-time size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
