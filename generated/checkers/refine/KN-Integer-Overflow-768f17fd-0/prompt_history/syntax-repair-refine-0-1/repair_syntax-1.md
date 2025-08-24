## Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

## Instruction

The following checker fails to compile, and your task is to resolve the compilation error based on the provided error messages.

Here are some potential ways to fix the issue:

1. Use the correct API: The current API may not exist, or the class has no such member. Replace it with an appropriate one.

2. Use correct arguments: Ensure the arguments passed to the API have the correct types and the correct number.

3. Change the variable types: Adjust the types of some variables based on the error messages.

4. Be careful if you want to include a header file. Please make sure the header file exists. For instance "fatal error: clang/StaticAnalyzer/Core/PathDiagnostic.h: No such file or directory".

**The version of Clang environment is Clang-18. You should consider the API compatibility.**

**Please only repair the failed parts and keep the original semantics.**
**Please return the whole checker code after fixing the compilation error.**

## Suggestions

1. Please only use two types of bug reports:
  - BasicBugReport (const BugType &bt, StringRef desc, PathDiagnosticLocation l)
  - PathSensitiveBugReport (const BugType &bt, StringRef desc, const ExplodedNode *errorNode)
  - PathSensitiveBugReport (const BugType &bt, StringRef shortDesc, StringRef desc, const ExplodedNode *errorNode)

## Example

- Error Line: 48 |   Optional<DefinedOrUnknownSVal> SizeSVal;

  - Error Messages: ‘Optional’ was not declared in this scope; did you mean ‘clang::ObjCImplementationControl::Optional’?

  - Fix: Replace 'Optional<DefinedOrUnknownSVal>' with 'std::optional<DefinedOrUnknownSVal>', and include the appropriate header.

- Error Line: 113 |     const MemRegion *MR = Entry.first;

    - Error Messages: unused variable ‘MR’ [-Wunused-variable]

    - Fix: Remove the variable 'MR' if it is not used.

## Checker

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
#include "clang/AST/ExprCXX.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the prompt.
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);

struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};

bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams);
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
  SAGenTestChecker() : BT(new BugType(this, "Narrow shift widened to 64-bit", "Integer")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                   CheckerContext &C, StringRef Ctx) const;

  static const BinaryOperator *findShiftInTree(const Stmt *S);
  static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);

  // New helpers to reduce false positives while preserving true positives.

  // Returns true if E is syntactically the integer literal 1 (with any suffix),
  // ignoring parentheses and implicit casts.
  static bool isLiteralOne(const Expr *E) {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
      // Treat 1 of any width/signedness as "literal one"
      return IL->getValue() == 1;
    }
    return false;
  }

  // Try to compute an unsigned upper bound for the value of E:
  //  - Prefer compile-time evaluation (EvaluateExprToInt).
  //  - Otherwise use path-sensitive constraint manager (inferSymbolMaxVal).
  // Returns true and sets Out if successful and value is non-negative.
  static bool getUnsignedUpperBound(const Expr *E, CheckerContext &C, uint64_t &Out) {
    if (!E)
      return false;

    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, E, C)) {
      if (EvalRes.isSigned() && EvalRes.isNegative())
        return false;
      Out = EvalRes.getZExtValue();
      return true;
    }

    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    if (SymbolRef Sym = V.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        if (Max->isSigned() && Max->isNegative())
          return false;
        Out = Max->getZExtValue();
        return true;
      }
    }
    return false;
  }

  // Try to compute an upper bound on the highest possible set bit index of E.
  // For example, if max(E) <= 7 (0b111), returns 2.
  // Only considers non-negative values. Returns true if successful.
  static bool getMaxBitIndexUpperBound(const Expr *E, CheckerContext &C, unsigned &Idx) {
    if (!E)
      return false;

    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, E, C)) {
      if (EvalRes.isSigned() && EvalRes.isNegative())
        return false;
      if (EvalRes == 0) {
        Idx = 0;
        return true;
      }
      llvm::APInt V = EvalRes.getExtValue() >= 0
                        ? EvalRes.getExtValue()
                        : llvm::APInt(EvalRes.getBitWidth(), 0);
      unsigned BitWidth = V.getBitWidth();
      unsigned LZ = V.countLeadingZeros();
      if (LZ >= BitWidth) {
        Idx = 0;
      } else {
        Idx = BitWidth - 1 - LZ;
      }
      return true;
    }

    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    if (SymbolRef Sym = V.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        if (Max->isSigned() && Max->isNegative())
          return false;
        if (*Max == 0) {
          Idx = 0;
          return true;
        }
        llvm::APInt A = Max->getExtValue() >= 0
                          ? Max->getExtValue()
                          : llvm::APInt(Max->getBitWidth(), 0);
        unsigned BitWidth = A.getBitWidth();
        unsigned LZ = A.countLeadingZeros();
        if (LZ >= BitWidth) {
          Idx = 0;
        } else {
          Idx = BitWidth - 1 - LZ;
        }
        return true;
      }
    }
    return false;
  }

  // Decide if the found shift is a false positive given the current path state.
  // Suppress when:
  //  - Shift amount is proven to be < promoted LHS width AND
  //    a) LHS is literal one (bitmask construction), OR
  //    b) we can prove (max_bit_index(LHS) + max_shift) < promoted LHS width.
  static bool isFalsePositive(const BinaryOperator *Shl, unsigned PromotedLHSWidth,
                              CheckerContext &C) {
    if (!Shl)
      return false;
    const Expr *L = Shl->getLHS();
    const Expr *R = Shl->getRHS();
    if (!L || !R)
      return false;

    uint64_t ShiftUB = 0;
    if (!getUnsignedUpperBound(R, C, ShiftUB))
      return false; // Can't prove anything, don't suppress.

    if (ShiftUB >= PromotedLHSWidth)
      return false; // May exceed width, keep the warning.

    // Bitmask-of-one: safe if shift < width.
    if (isLiteralOne(L))
      return true;

    // More general: if we can bound the maximum bit index of LHS and
    // the sum stays within promoted width, it's safe.
    unsigned LMaxIdx = 0;
    if (getMaxBitIndexUpperBound(L, C, LMaxIdx)) {
      if ((uint64_t)LMaxIdx + ShiftUB < PromotedLHSWidth)
        return true;
    }

    return false;
  }
};

static const BinaryOperator *asShift(const Stmt *S) {
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Shl)
      return BO;
  }
  return nullptr;
}

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

  // Find a left-shift operator within the expression tree.
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

  // The type of the shift expression is the type of the promoted left operand.
  unsigned PromotedLHSWidth = ACtx.getIntWidth(ShlTy);
  if (PromotedLHSWidth >= 64)
    return; // Shift already performed in >=64-bit, OK.

  // If there is an explicit cast to >=64-bit within the LHS subtree, suppress.
  if (hasExplicitCastToWide64(L, ACtx))
    return;

  // If path constraints prove this shift is safe (see isFalsePositive), suppress.
  if (isFalsePositive(Shl, PromotedLHSWidth, C))
    return;

  // Otherwise, report.
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
  // Only handle assignments: LHS = RHS or compound assignments (e.g., |=).
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

```

## Error Messages

- Error Line: 130 |       llvm::APInt V = EvalRes.getExtValue() >= 0

	- Error Messages: perands to ‘?:’ have different types ‘int64_t’ {aka ‘long int’} and ‘llvm::APInt’

- Error Line: 153 |         llvm::APInt A = Max->getExtValue() >= 0

	- Error Messages: perands to ‘?:’ have different types ‘int64_t’ {aka ‘long int’} and ‘llvm::APInt’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
