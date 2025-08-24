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
#include "clang/AST/Type.h"
#include "llvm/ADT/StringRef.h"
#include <algorithm>
#include <cctype>
#include <optional>

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

// Track per-variable coarse upper bounds learned from assignments.
// Key: VarDecl*, Value: APSInt upper bound (unsigned).
namespace clang { namespace ento {
REGISTER_MAP_WITH_PROGRAMSTATE(VarUpperBoundMap, const VarDecl *, llvm::APSInt)
}} // namespace clang::ento

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

  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  static bool constantShiftFitsInLHSWidth(const Expr *L, const Expr *R,
                                          unsigned LHSW, CheckerContext &C) {
    llvm::APSInt LHSEval, RHSEval;
    if (!EvaluateExprToInt(LHSEval, L, C))
      return false;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;

    if (LHSEval.isSigned() && LHSEval.isNegative())
      return false;

    unsigned LBits = LHSEval.getActiveBits();
    uint64_t ShiftAmt = RHSEval.getZExtValue();
    if (LBits == 0)
      return true;
    return (uint64_t)LBits + ShiftAmt <= (uint64_t)LHSW;
  }

  static bool isAnyLongType(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::Long) ||
           QT->isSpecificBuiltinType(BuiltinType::ULong);
  }

  static bool isFixed64Builtin(QualType QT) {
    return QT->isSpecificBuiltinType(BuiltinType::LongLong) ||
           QT->isSpecificBuiltinType(BuiltinType::ULongLong);
  }

  static bool calleeNameLooksLikeIOOrReg(StringRef Name) {
    llvm::SmallString<64> Lower(Name);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("read") || S.contains("write") || S.contains("peek") ||
           S.contains("poke") || S.contains("in") || S.contains("out") ||
           S.contains("io") || S.contains("reg");
  }

  static bool paramNameLooksLikeAddrOffset(const ParmVarDecl *P) {
    if (!P)
      return false;
    StringRef N = P->getName();
    if (N.empty())
      return false;

    llvm::SmallString<64> Lower(N);
    for (char &c : Lower)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    StringRef S(Lower);
    return S.contains("addr") || S.contains("address") || S.contains("offset") ||
           S.contains("ofs") || S.contains("reg") || S.contains("index") ||
           S.contains("port") || S.contains("bar");
  }

  static bool tryGetConstShiftAmount(const Expr *R, CheckerContext &C, uint64_t &Out) {
    llvm::APSInt RHSEval;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;
    Out = RHSEval.getZExtValue();
    return true;
  }

  static bool findCallParentAndArgIndex(const Expr *E, CheckerContext &C,
                                        const CallExpr *&OutCE, unsigned &OutIdx) {
    OutCE = findSpecificTypeInParents<CallExpr>(E, C);
    if (!OutCE)
      return false;

    const Expr *PE = peel(E);
    unsigned ArgCount = OutCE->getNumArgs();
    for (unsigned i = 0; i < ArgCount; ++i) {
      const Expr *AE = OutCE->getArg(i);
      if (peel(AE) == PE) {
        OutIdx = i;
        return true;
      }
    }
       return false;
  }

  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     QualType DestTy,
                                     CheckerContext &C,
                                     StringRef Ctx) {
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    if (Ctx == "argument") {
      const CallExpr *CE = nullptr;
      unsigned ArgIdx = 0;
      if (findCallParentAndArgIndex(WholeExpr, C, CE, ArgIdx)) {
        const FunctionDecl *FD = CE->getDirectCallee();
        const ParmVarDecl *PVD = nullptr;
        if (FD && ArgIdx < FD->getNumParams())
          PVD = FD->getParamDecl(ArgIdx);

        if (isAnyLongType(DestTy))
          return true;

        if (PVD && paramNameLooksLikeAddrOffset(PVD))
          return true;

        if (FD) {
          if (const IdentifierInfo *ID = FD->getIdentifier()) {
            if (calleeNameLooksLikeIOOrReg(ID->getName()))
              return true;
          }
        }

        uint64_t K = 0;
        if (tryGetConstShiftAmount(Shl->getRHS(), C, K) && K <= 3)
          return true;
      }
    }

    return false;
  }

  // Extract a coarse upper bound from an assignment RHS by scanning integer literals.
  // Intended to capture patterns like min(x, CONST) where CONST is the controlling bound.
  static bool extractUpperBoundLiteralFromRHS(const Expr *RHS, CheckerContext &C,
                                              llvm::APSInt &Out) {
    if (!RHS)
      return false;

    // Walk the subtree, find the maximum integer literal value.
    llvm::APSInt MaxVal(64, true); // unsigned
    bool Found = false;

    llvm::SmallVector<const Stmt *, 16> Worklist;
    Worklist.push_back(RHS);
    while (!Worklist.empty()) {
      const Stmt *Cur = Worklist.pop_back_val();
      if (!Cur) continue;

      if (const auto *IL = dyn_cast<IntegerLiteral>(Cur)) {
        llvm::APInt V = IL->getValue();
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *CharL = dyn_cast<CharacterLiteral>(Cur)) {
        llvm::APInt V(64, CharL->getValue());
        if (!Found || V.ugt(MaxVal))
          MaxVal = llvm::APSInt(V, /*isUnsigned=*/true);
        Found = true;
      } else if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
        // Try to handle sizeof-like folds that may appear as integral casts.
        // We still just traverse.
        if (const Expr *SubE = UO->getSubExpr())
          Worklist.push_back(SubE);
      } else {
        for (const Stmt *Child : Cur->children())
          if (Child)
            Worklist.push_back(Child);
      }
    }

    if (Found) {
      Out = MaxVal;
      return true;
    }
    return false;
  }

  // Get a recorded per-variable upper bound from program state.
  static bool getRecordedVarUpperBound(const Expr *E, CheckerContext &C,
                                       llvm::APSInt &Out) {
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(peel(E));
    if (!DRE)
      return false;
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    ProgramStateRef State = C.getState();
    const llvm::APSInt *Stored = State->get<VarUpperBoundMap>(VD);
    if (!Stored)
      return false;
    Out = *Stored;
    return true;
  }

  // Compute an upper bound for an expression based on:
  // - Exact constant evaluation
  // - Recorded per-variable upper bounds
  // - Simple addition of sub-bounds
  static bool computeExprUpperBound(const Expr *E, CheckerContext &C,
                                    llvm::APSInt &Out) {
    if (!E)
      return false;
    E = peel(E);

    // Constant?
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      if (Val.isSigned() && Val.isNegative())
        return false; // not handling negative bounds here
      Out = Val.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }

    // Variable with recorded bound?
    if (getRecordedVarUpperBound(E, C, Out))
      return true;

    // Symbolic? Try constraint manager max.
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(E, C.getLocationContext());
    if (std::optional<nonloc::ConcreteInt> CI = SV.getAs<nonloc::ConcreteInt>()) {
      llvm::APSInt CIVal = CI->getValue();
      if (CIVal.isSigned() && CIVal.isNegative())
        return false;
      Out = CIVal.extOrTrunc(64);
      Out.setIsUnsigned(true);
      return true;
    }
    if (SymbolRef Sym = SV.getAsSymbol()) {
      if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
        llvm::APSInt M = *Max;
        if (M.isSigned() && M.isNegative())
          return false;
        Out = M.extOrTrunc(64);
        Out.setIsUnsigned(true);
        return true;
      }
    }

    // Composite expressions: try L + R for additions
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Add) {
        llvm::APSInt LUB, RUB;
        if (computeExprUpperBound(BO->getLHS(), C, LUB) &&
            computeExprUpperBound(BO->getRHS(), C, RUB)) {
          unsigned BW = std::max(LUB.getBitWidth(), RUB.getBitWidth());
          llvm::APSInt L2 = LUB.extOrTrunc(BW);
          llvm::APSInt R2 = RUB.extOrTrunc(BW);
          L2.setIsUnsigned(true);
          R2.setIsUnsigned(true);
          Out = L2 + R2;
          Out.setIsUnsigned(true);
          return true;
        }
      }
      // Other ops: give up (conservative)
    }

    return false;
  }

  // Compute maximum number of active bits an expression's value can have,
  // using constants or recorded/symbolic upper bounds.
  static bool computeExprMaxActiveBits(const Expr *E, CheckerContext &C,
                                       unsigned &OutBits) {
    if (!E)
      return false;
    E = peel(E);

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, E, C)) {
      if (Val.isSigned() && Val.isNegative())
        return false;
      OutBits = Val.getActiveBits();
      return true;
    }

    llvm::APSInt UB;
    if (computeExprUpperBound(E, C, UB)) {
      // Active bits of the upper bound is an upper bound on the active bits.
      OutBits = UB.getActiveBits();
      return true;
    }

    return false;
  }

  // Decide if the shift is provably safe within the LHS bitwidth (e.g., 32-bit)
  // under computed upper bounds for L and R.
  static bool shiftSafeUnderUpperBounds(const Expr *L, const Expr *R,
                                        unsigned LHSW, CheckerContext &C) {
    unsigned MaxLBits = 0;
    if (!computeExprMaxActiveBits(L, C, MaxLBits))
      return false;

    llvm::APSInt RMax;
    if (!computeExprUpperBound(R, C, RMax))
      return false;

    uint64_t ShiftMax = RMax.getZExtValue();

    if (MaxLBits == 0)
      return true;

    return (uint64_t)MaxLBits + ShiftMax <= (uint64_t)LHSW;
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
                                                   CheckerContext &C, StringRef Ctx) const {
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

  if (!L->getType()->isIntegerType())
    return;

  unsigned LHSW = ACtx.getIntWidth(L->getType());
  if (LHSW >= 64)
    return; // LHS already wide.

  if (hasExplicitCastToWide64(L, ACtx))
    return;

  if (isFalsePositiveContext(E, Shl, DestTy, C, Ctx))
    return;

  // Constant proof: safely fits.
  if (constantShiftFitsInLHSWidth(L, R, LHSW, C))
    return;

  // New: Symbolic upper-bound proof: if we can prove the result fits in 32-bit,
  // suppress. This addresses cases like: pool_size = 1 << (PAGE_SHIFT + order),
  // where 'order' was clamped by min(..., MAX_PAGE_ORDER).
  if (shiftSafeUnderUpperBounds(L, R, LHSW, C))
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

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  // First, perform shift-to-wide analysis for assignment context.
  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");

  // Second, update per-variable upper bounds when possible to help suppress FPs.
  const auto *DRE = dyn_cast<DeclRefExpr>(peel(LHS));
  if (!DRE)
    return;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  llvm::APSInt BoundLit;
  if (extractUpperBoundLiteralFromRHS(RHS, C, BoundLit)) {
    // Store or update with the maximum bound seen.
    ProgramStateRef State = C.getState();
    const llvm::APSInt *Cur = State->get<VarUpperBoundMap>(VD);
    llvm::APSInt NewBound = BoundLit;
    if (Cur && Cur->ugt(NewBound))
      NewBound = *Cur;
    ProgramStateRef NewState = State->set<VarUpperBoundMap>(VD, NewBound);
    if (NewState != State)
      C.addTransition(NewState);
  }
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

    ASTContext &ACtx = C.getASTContext();
    if (!DestTy->isIntegerType() || ACtx.getIntWidth(DestTy) < 64)
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

- Error Line: 42 |   struct ProgramStateTrait<Name> : public ProgramStatePartialTrait<Name##Ty> { \

	- Error Messages: specialization of ‘template<class T> struct clang::ento::ProgramStateTrait’ in different namespace [-fpermissive]

- Error Line: 42 |   struct ProgramStateTrait<Name> : public ProgramStatePartialTrait<Name##Ty> { \

	- Error Messages: xplicit specialization of ‘template<class T> struct clang::ento::ProgramStateTrait’ outside its namespace must use a nested-name-specifier [-fpermissive]

- Error Line: 43 |     static void *GDMIndex() {                                                  \

	- Error Messages: definition of ‘static void* clang::ento::ProgramStateTrait<clang::ento::{anonymous}::VarUpperBoundMap>::GDMIndex()’ is not in namespace enclosing ‘clang::ento::ProgramStateTrait<clang::ento::{anonymous}::VarUpperBoundMap>’ [-fpermissive]



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
