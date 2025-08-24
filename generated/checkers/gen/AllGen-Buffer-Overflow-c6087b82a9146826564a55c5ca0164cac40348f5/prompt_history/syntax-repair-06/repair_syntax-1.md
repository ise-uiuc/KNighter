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
#include "clang/AST/Type.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(SizeBoundMap, const MemRegion*, const MemRegion*)

namespace {
class SAGenTestChecker : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded user copy into fixed-size buffer", "Memory Safety")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      bool isCopyFromUser(const CallEvent &Call, CheckerContext &C) const;
      bool getFixedCharArrayInfo(const DeclRefExpr *DRE, CheckerContext &C,
                                 llvm::APInt &ArraySize, const MemRegion *&ArrayReg) const;
      bool countExprIsClampedToArray(const Expr *CountE, StringRef BufName,
                                     const MemRegion *BufReg, CheckerContext &C) const;
      const Expr *getRHSForBind(const Stmt *S, const MemRegion *LHSReg, CheckerContext &C) const;
};

static bool isCharLike(QualType QT) {
  QT = QT.getUnqualifiedType();
  if (const Type *Ty = QT.getTypePtrOrNull()) {
    if (Ty->isCharType())
      return true;
    if (const BuiltinType *BT = dyn_cast<BuiltinType>(Ty)) {
      return BT->getKind() == BuiltinType::SChar ||
             BT->getKind() == BuiltinType::UChar;
    }
  }
  return false;
}

bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  // Use text-based name check as suggested to be robust.
  return ExprHasName(OriginExpr, "copy_from_user", C);
}

bool SAGenTestChecker::getFixedCharArrayInfo(const DeclRefExpr *DRE, CheckerContext &C,
                                             llvm::APInt &ArraySize,
                                             const MemRegion *&ArrayReg) const {
  if (!DRE)
    return false;

  // Check that the DeclRefExpr refers to a fixed-size array and get its size.
  if (!getArraySizeFromExpr(ArraySize, DRE))
    return false;

  // Verify the element type is char-like (char/signed char/unsigned char).
  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return false;

  QualType QT = VD->getType();
  const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr());
  if (!CAT)
    return false;

  if (!isCharLike(CAT->getElementType()))
    return false;

  // Get the MemRegion for the array variable.
  ArrayReg = getMemRegionFromExpr(DRE, C);
  if (!ArrayReg)
    return false;
  ArrayReg = ArrayReg->getBaseRegion();
  if (!ArrayReg)
    return false;

  return true;
}

bool SAGenTestChecker::countExprIsClampedToArray(const Expr *CountE, StringRef BufName,
                                                 const MemRegion *BufReg, CheckerContext &C) const {
  if (!CountE)
    return false;

  // 1) Constant check: if CountE is a constant <= sizeof(buf), it's safe.
  // We cannot compute sizeof(buf) here without array size, so this branch
  // will be handled by the caller when they know the array size.
  // Here we only handle text/state checks.

  // 2) Textual clamp using sizeof and optionally min/min_t.
  bool HasSizeof = ExprHasName(CountE, "sizeof", C);
  bool MentionsBuf = ExprHasName(CountE, BufName, C);
  bool HasMin = ExprHasName(CountE, "min", C) || ExprHasName(CountE, "min_t", C);

  if (HasSizeof && MentionsBuf)
    return true; // e.g., sizeof(buf) - 1, or sizeof(buf)

  if (HasMin && HasSizeof && MentionsBuf)
    return true; // e.g., min(n, sizeof(buf) - 1)

  // 3) State-based clamp: has this CountE been previously bounded to this array?
  const MemRegion *CountReg = getMemRegionFromExpr(CountE, C);
  if (CountReg) {
    CountReg = CountReg->getBaseRegion();
    if (CountReg) {
      ProgramStateRef State = C.getState();
      const MemRegion *BoundTo = State->get<SizeBoundMap>(CountReg);
      if (BoundTo && BoundTo->getBaseRegion() == BufReg)
        return true;
    }
  }

  return false;
}

const Expr *SAGenTestChecker::getRHSForBind(const Stmt *S, const MemRegion *LHSReg, CheckerContext &C) const {
  if (!S || !LHSReg)
    return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      return BO->getRHS();
  }

  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    if (!DS->isSingleDecl()) {
      // Try to match the decl whose region equals LHSReg.
      for (const Decl *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (!VD->hasInit())
            continue;
          // Construct the region for this VD and compare.
          const MemRegion *VR =
              C.getStoreManager().getRegionManager().getVarRegion(VD, C.getLocationContext());
          if (!VR) continue;
          VR = VR->getBaseRegion();
          if (!VR) continue;
          if (VR == LHSReg)
            return VD->getInit();
        }
      }
    } else {
      const Decl *D = DS->getSingleDecl();
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (VD->hasInit())
          return VD->getInit();
      }
    }
  }

  return nullptr;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCopyFromUser(Call, C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DstE = Call.getArgExpr(0);
  const Expr *CountE = Call.getArgExpr(2);
  if (!DstE || !CountE)
    return;

  // Find the underlying DeclRefExpr of the destination buffer.
  const DeclRefExpr *BufDRE = findSpecificTypeInChildren<DeclRefExpr>(DstE);
  if (!BufDRE)
    return;

  // Get fixed-size char array info and its region.
  llvm::APInt ArraySizeBits;
  const MemRegion *BufReg = nullptr;
  if (!getFixedCharArrayInfo(BufDRE, C, ArraySizeBits, BufReg))
    return;

  // Heuristic safety checks on CountE:
  // A) Constant evaluation
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, CountE, C)) {
    // If the count is a constant and <= array size, it's safe.
    // Compare as unsigned (size_t) semantics.
    if (EvalRes.isUnsigned() || EvalRes >= 0) {
      llvm::APInt CountVal = EvalRes.isUnsigned()
                                 ? EvalRes.getUnsigned()
                                 : EvalRes.getExtValue();
      if (CountVal.ule(ArraySizeBits))
        return; // safe
      // If CountVal definitely exceeds ArraySize, report.
      // Note: copying exactly sizeof(buf) bytes is acceptable for raw bytes.
      // We'll treat strictly greater than array size as unsafe.
      if (CountVal.ugt(ArraySizeBits)) {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          return;
        auto R = std::make_unique<PathSensitiveBugReport>(
            *BT, "Unbounded copy_from_user into fixed-size buffer; clamp length to sizeof(buf)-1", N);
        R->addRange(Call.getSourceRange());
        C.emitReport(std::move(R));
        return;
      }
    }
  } else {
    // B) Text/state-based checks
    StringRef BufName = BufDRE->getDecl()->getName();
    if (countExprIsClampedToArray(CountE, BufName, BufReg, C))
      return; // safe
  }

  // If none of the safety checks passed, report.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unbounded copy_from_user into fixed-size buffer; clamp length to sizeof(buf)-1", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const Expr *RHS = getRHSForBind(S, LHSReg, C);
  if (!RHS)
    return;

  ProgramStateRef State = C.getState();

  // Case 1: RHS is a clamp expression involving sizeof(array) [with optional min/min_t].
  const DeclRefExpr *ArrayDRE = findSpecificTypeInChildren<DeclRefExpr>(RHS);
  llvm::APInt ArrSizeBits;
  const MemRegion *ArrayReg = nullptr;
  bool HasArray = false;
  if (ArrayDRE) {
    HasArray = getFixedCharArrayInfo(ArrayDRE, C, ArrSizeBits, ArrayReg);
  }

  if (HasArray) {
    bool HasSizeof = ExprHasName(RHS, "sizeof", C);
    bool MentionsBuf = ExprHasName(RHS, ArrayDRE->getDecl()->getName(), C);
    bool HasMin = ExprHasName(RHS, "min", C) || ExprHasName(RHS, "min_t", C);

    if ((HasSizeof && MentionsBuf) || (HasMin && HasSizeof && MentionsBuf)) {
      // Record that LHSReg is bounded to ArrayReg.
      State = State->set<SizeBoundMap>(LHSReg, ArrayReg->getBaseRegion());
      C.addTransition(State);
      return;
    }
  }

  // Case 2: Propagate from another variable: X = Y; and Y is known bounded to some array.
  if (const auto *RHSDRE = dyn_cast<DeclRefExpr>(RHS->IgnoreParenCasts())) {
    const MemRegion *RHSReg = getMemRegionFromExpr(RHSDRE, C);
    if (RHSReg) {
      RHSReg = RHSReg->getBaseRegion();
      if (RHSReg) {
        const MemRegion *BoundTo = State->get<SizeBoundMap>(RHSReg);
        if (BoundTo) {
          State = State->set<SizeBoundMap>(LHSReg, BoundTo->getBaseRegion());
          C.addTransition(State);
          return;
        }
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded copy_from_user into fixed-size buffers and suggests clamping length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 129 |       const MemRegion *BoundTo = State->get<SizeBoundMap>(CountReg);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization

- Error Line: 207 |                                  ? EvalRes.getUnsigned()

	- Error Messages: no matching function for call to ‘llvm::APSInt::getUnsigned()’

- Error Line: 285 |         const MemRegion *BoundTo = State->get<SizeBoundMap>(RHSReg);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
