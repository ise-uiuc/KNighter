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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Parallel-array index overflow", "Array bounds")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Helpers for loop recognition and array access analysis
      static bool getCanonicalLoop(const ForStmt *FS,
                                   const VarDecl *&LoopVar,
                                   const Expr *&BoundExpr,
                                   bool &IsStrictLess,
                                   ASTContext &Ctx);

      static bool evalToInt(const Expr *E, APSInt &Out, ASTContext &Ctx);

      static bool indexIsLoopVar(const Expr *Idx, const VarDecl *V);

      static bool getArraySizeFromSubscriptBase(const Expr *Base, llvm::APInt &ArraySize, ASTContext &Ctx);

      static std::string getArrayName(const Expr *Base);

      void report(const ArraySubscriptExpr *ASE,
                  uint64_t BoundVal,
                  StringRef ArrName,
                  uint64_t ArrSize,
                  BugReporter &BR,
                  ASTContext &Ctx) const;
};

//========================== Helper Implementations ==========================//

bool SAGenTestChecker::evalToInt(const Expr *E, APSInt &Out, ASTContext &Ctx) {
  if (!E)
    return false;
  Expr::EvalResult ER;
  if (E->EvaluateAsInt(ER, Ctx)) {
    Out = ER.Val.getInt();
    return true;
  }
  return false;
}

bool SAGenTestChecker::getCanonicalLoop(const ForStmt *FS,
                                        const VarDecl *&LoopVar,
                                        const Expr *&BoundExpr,
                                        bool &IsStrictLess,
                                        ASTContext &Ctx) {
  LoopVar = nullptr;
  BoundExpr = nullptr;
  IsStrictLess = true;

  if (!FS)
    return false;

  // 1) Init: either "int i = 0;" or "i = 0;"
  const Stmt *InitS = FS->getInit();
  const VarDecl *V = nullptr;

  if (const auto *DS = dyn_cast_or_null<DeclStmt>(InitS)) {
    if (!DS->isSingleDecl())
      return false;
    const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
    if (!VD || !VD->hasInit())
      return false;
    APSInt InitVal;
    if (!evalToInt(VD->getInit()->IgnoreParenImpCasts(), InitVal, Ctx))
      return false;
    if (InitVal != 0)
      return false;
    V = VD;
  } else if (const auto *BO = dyn_cast_or_null<BinaryOperator>(InitS)) {
    if (BO->getOpcode() != BO_Assign)
      return false;
    const auto *LHS = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
    if (!LHS)
      return false;
    const auto *VD = dyn_cast<VarDecl>(LHS->getDecl());
    if (!VD)
      return false;
    APSInt InitVal;
    if (!evalToInt(BO->getRHS()->IgnoreParenImpCasts(), InitVal, Ctx))
      return false;
    if (InitVal != 0)
      return false;
    V = VD;
  } else {
    return false;
  }

  // 2) Condition: "i < Bound" or "i <= Bound"
  const Expr *CondE = FS->getCond();
  if (!CondE)
    return false;
  CondE = CondE->IgnoreParenImpCasts();
  const auto *CBO = dyn_cast<BinaryOperator>(CondE);
  if (!CBO)
    return false;

  BinaryOperator::Opcode Op = CBO->getOpcode();
  if (Op != BO_LT && Op != BO_LE)
    return false;

  const auto *L = dyn_cast<DeclRefExpr>(CBO->getLHS()->IgnoreParenImpCasts());
  if (!L)
    return false;
  const auto *LVD = dyn_cast<VarDecl>(L->getDecl());
  if (!LVD || LVD != V)
    return false;

  IsStrictLess = (Op == BO_LT);
  BoundExpr = CBO->getRHS();

  // We do not strictly enforce increment pattern, as per plan.

  LoopVar = V;
  return true;
}

bool SAGenTestChecker::indexIsLoopVar(const Expr *Idx, const VarDecl *V) {
  if (!Idx || !V)
    return false;
  Idx = Idx->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Idx)) {
    return DRE->getDecl() == V;
  }
  return false;
}

bool SAGenTestChecker::getArraySizeFromSubscriptBase(const Expr *Base, llvm::APInt &ArraySize, ASTContext &Ctx) {
  if (!Base)
    return false;

  // Case 1: direct DeclRefExpr to a variable with ConstantArrayType
  if (getArraySizeFromExpr(ArraySize, Base))
    return true;

  // Case 2: MemberExpr (struct or pointer-to-struct field)
  const MemberExpr *ME = dyn_cast<MemberExpr>(Base->IgnoreParenImpCasts());
  if (!ME) {
    // Try searching downward as a fallback
    ME = findSpecificTypeInChildren<MemberExpr>(Base);
  }
  if (ME) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      QualType T = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(T.getTypePtr())) {
        ArraySize = CAT->getSize();
        return true;
      }
    }
  }

  // Unknown or pointer-based indexing: skip
  return false;
}

std::string SAGenTestChecker::getArrayName(const Expr *Base) {
  if (!Base)
    return std::string();

  Base = Base->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
    if (const auto *VD = dyn_cast<ValueDecl>(DRE->getDecl()))
      return VD->getNameAsString();
  }

  if (const auto *ME = dyn_cast<MemberExpr>(Base)) {
    if (const auto *VD = dyn_cast<ValueDecl>(ME->getMemberDecl()))
      return VD->getNameAsString();
  }

  // Fallback: try to find a nested MemberExpr
  if (const auto *ME2 = findSpecificTypeInChildren<MemberExpr>(Base)) {
    if (const auto *VD = dyn_cast<ValueDecl>(ME2->getMemberDecl()))
      return VD->getNameAsString();
  }

  return std::string();
}

void SAGenTestChecker::report(const ArraySubscriptExpr *ASE,
                              uint64_t BoundVal,
                              StringRef ArrName,
                              uint64_t ArrSize,
                              BugReporter &BR,
                              ASTContext &Ctx) const {
  if (!ASE)
    return;

  SmallString<128> Msg;
  llvm::raw_svector_ostream OS(Msg);
  OS << "Loop bound " << BoundVal << " exceeds array '" << ArrName
     << "' size " << ArrSize << "; " << ArrName << "[i] may be out of bounds";

  PathDiagnosticLocation Loc =
      PathDiagnosticLocation::createBegin(ASE, BR.getSourceManager(), Ctx);

  auto R = std::make_unique<BasicBugReport>(*BT, OS.str(), Loc);
  R->addRange(ASE->getSourceRange());
  BR.emitReport(std::move(R));
}

//============================ Main AST Callback =============================//

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D)
    return;
  const Stmt *Body = D->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = Mgr.getASTContext();

  // Visitor to find ForStmt and analyze them.
  class Visitor : public RecursiveASTVisitor<Visitor> {
    const SAGenTestChecker *Checker;
    BugReporter &BR;
    ASTContext &Ctx;

  public:
    Visitor(const SAGenTestChecker *Checker, BugReporter &BR, ASTContext &Ctx)
        : Checker(Checker), BR(BR), Ctx(Ctx) {}

    bool VisitForStmt(const ForStmt *FS) {
      const VarDecl *LoopVar = nullptr;
      const Expr *BoundExpr = nullptr;
      bool IsStrictLess = true;

      if (!SAGenTestChecker::getCanonicalLoop(FS, LoopVar, BoundExpr, IsStrictLess, Ctx))
        return true;

      APSInt BoundAPS;
      if (!SAGenTestChecker::evalToInt(BoundExpr->IgnoreParenImpCasts(), BoundAPS, Ctx))
        return true;

      uint64_t BoundVal = BoundAPS.isSigned() ? BoundAPS.getExtValue() : BoundAPS.getZExtValue();
      // We only handle non-negative bounds
      if ((BoundAPS.isSigned() && BoundAPS.isNegative()))
        return true;

      // Collect array subscripts with index equal to the loop variable
      class BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
        const VarDecl *V;
        llvm::SmallVector<const ArraySubscriptExpr *, 8> &Out;
      public:
        BodyVisitor(const VarDecl *V, llvm::SmallVector<const ArraySubscriptExpr *, 8> &Out)
            : V(V), Out(Out) {}

        bool VisitArraySubscriptExpr(const ArraySubscriptExpr *ASE) {
          if (!ASE)
            return true;
          const Expr *Idx = ASE->getIdx();
          if (SAGenTestChecker::indexIsLoopVar(Idx, V)) {
            Out.push_back(ASE);
          }
          return true;
        }
      };

      llvm::SmallVector<const ArraySubscriptExpr *, 8> Accesses;
      BodyVisitor BV(LoopVar, Accesses);
      if (const Stmt *LoopBody = FS->getBody())
        BV.TraverseStmt(const_cast<Stmt *>(LoopBody));

      // Report per array per loop (avoid duplicates)
      llvm::SmallPtrSet<const ValueDecl *, 8> Reported;

      for (const ArraySubscriptExpr *ASE : Accesses) {
        if (!ASE)
          continue;

        llvm::APInt ArrSizeAP;
        if (!SAGenTestChecker::getArraySizeFromSubscriptBase(ASE->getBase(), ArrSizeAP, Ctx))
          continue;

        uint64_t ArrSize = ArrSizeAP.getLimitedValue(UINT64_MAX);

        bool IsBug = false;
        if (IsStrictLess) {
          // for (i = 0; i < Bound) accessing A[i]: overflow if Bound > ArrSize
          if (BoundVal > ArrSize)
            IsBug = true;
        } else {
          // for (i = 0; i <= Bound) accessing A[i]: overflow if Bound >= ArrSize
          if (BoundVal >= ArrSize)
            IsBug = true;
        }

        if (!IsBug)
          continue;

        // Identify the array's ValueDecl to deduplicate
        const ValueDecl *VDKey = nullptr;
        const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
          VDKey = dyn_cast<ValueDecl>(DRE->getDecl());
        } else if (const auto *ME = dyn_cast<MemberExpr>(Base)) {
          VDKey = dyn_cast<ValueDecl>(ME->getMemberDecl());
        } else if (const auto *ME2 = findSpecificTypeInChildren<MemberExpr>(ASE->getBase())) {
          VDKey = dyn_cast<ValueDecl>(ME2->getMemberDecl());
        }

        if (VDKey && Reported.contains(VDKey))
          continue;
        if (VDKey)
          Reported.insert(VDKey);

        std::string Name = SAGenTestChecker::getArrayName(ASE->getBase());
        Checker->report(ASE, BoundVal, Name.empty() ? StringRef("array") : StringRef(Name),
                        ArrSize, BR, Ctx);
      }

      return true;
    }
  };

  Visitor V(this, BR, Ctx);
  V.TraverseStmt(const_cast<Stmt *>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect loops that index into a smaller parallel array using a larger loop bound",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 48 |       static bool evalToInt(const Expr *E, APSInt &Out, ASTContext &Ctx);

	- Error Messages: ‘APSInt’ has not been declared

- Error Line: 66 | bool SAGenTestChecker::evalToInt(const Expr *E, APSInt &Out, ASTContext &Ctx) {

	- Error Messages: ‘APSInt’ has not been declared

- Error Line: 71 |     Out = ER.Val.getInt();

	- Error Messages: cannot convert ‘clang::APValue::APSInt’ {aka ‘llvm::APSInt’} to ‘int’ in assignment

- Error Line: 99 |     APSInt InitVal;

	- Error Messages: ‘APSInt’ was not declared in this scope; did you mean ‘llvm::APSInt’?

- Error Line: 100 |     if (!evalToInt(VD->getInit()->IgnoreParenImpCasts(), InitVal, Ctx))

	- Error Messages: ‘InitVal’ was not declared in this scope; did you mean ‘InitS’?

- Error Line: 102 |     if (InitVal != 0)

	- Error Messages: ‘InitVal’ was not declared in this scope; did you mean ‘InitS’?

- Error Line: 114 |     APSInt InitVal;

	- Error Messages: ‘APSInt’ was not declared in this scope; did you mean ‘llvm::APSInt’?

- Error Line: 115 |     if (!evalToInt(BO->getRHS()->IgnoreParenImpCasts(), InitVal, Ctx))

	- Error Messages: ‘InitVal’ was not declared in this scope; did you mean ‘InitS’?

- Error Line: 117 |     if (InitVal != 0)

	- Error Messages: ‘InitVal’ was not declared in this scope; did you mean ‘InitS’?

- Error Line: 231 |       PathDiagnosticLocation::createBegin(ASE, BR.getSourceManager(), Ctx);

	- Error Messages: no matching function for call to ‘clang::ento::PathDiagnosticLocation::createBegin(const clang::ArraySubscriptExpr*&, const clang::SourceManager&, clang::ASTContext&)’

- Error Line: 267 |       APSInt BoundAPS;

	- Error Messages: ‘APSInt’ was not declared in this scope; did you mean ‘llvm::APSInt’?

- Error Line: 268 |       if (!SAGenTestChecker::evalToInt(BoundExpr->IgnoreParenImpCasts(), BoundAPS, Ctx))

	- Error Messages: ‘BoundAPS’ was not declared in this scope

- Error Line: 271 |       uint64_t BoundVal = BoundAPS.isSigned() ? BoundAPS.getExtValue() : BoundAPS.getZExtValue();

	- Error Messages: ‘BoundAPS’ was not declared in this scope



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
