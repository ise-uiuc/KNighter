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
#include "clang/AST/Attr.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: set of zero-initialized heap/object base regions.
REGISTER_SET_WITH_PROGRAMSTATE(ZeroedObjs, const MemRegion *)
// Program state: set of base object regions whose counted_by counter is initialized.
REGISTER_SET_WITH_PROGRAMSTATE(CounterInitializedObjs, const MemRegion *)

namespace {

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::Bind,
      check::Location
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use of __counted_by flexible-array before counter init", "Memory Safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool isZeroAllocator(const CallEvent &Call, CheckerContext &C);
      static bool isMemWriteLike(const CallEvent &Call, CheckerContext &C,
                                 unsigned &DestIdx, unsigned &LenIdx);
      static bool isNonZeroLengthArg(const CallEvent &Call, unsigned LenIdx, CheckerContext &C);

      static const FieldDecl *getMemberFieldDecl(const Expr *E);
      static const MemRegion *getBaseObjectRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C);

      static bool isCountedByFlexibleArrayField(const FieldDecl *FD, const FieldDecl *&CounterFD);
      static bool isCounterFieldForAnyCountedBy(const FieldDecl *FD);

      void reportFlexibleArrayBeforeCounterInit(const Stmt *S, CheckerContext &C) const;
};

// Return true if kernel allocator returns zeroed memory.
bool SAGenTestChecker::isZeroAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, "kzalloc", C) ||
         ExprHasName(Origin, "kvzalloc", C) ||
         ExprHasName(Origin, "kcalloc", C) ||
         ExprHasName(Origin, "devm_kzalloc", C);
}

// Return true if Call is a memory-write-like function and set DestIdx/LenIdx.
bool SAGenTestChecker::isMemWriteLike(const CallEvent &Call, CheckerContext &C,
                                      unsigned &DestIdx, unsigned &LenIdx) {
  DestIdx = 0;
  LenIdx = 2;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  if (ExprHasName(Origin, "memcpy", C) ||
      ExprHasName(Origin, "memmove", C) ||
      ExprHasName(Origin, "memset", C)) {
    // All three have length at index 2.
    return true;
  }
  return false;
}

// Determine whether the length argument is possibly non-zero.
// If we can't evaluate, assume possibly non-zero (return true).
bool SAGenTestChecker::isNonZeroLengthArg(const CallEvent &Call, unsigned LenIdx, CheckerContext &C) {
  if (LenIdx >= Call.getNumArgs())
    return true;

  const Expr *LenE = Call.getArgExpr(LenIdx);
  if (!LenE)
    return true;

  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, LenE, C)) {
    return Val != 0;
  }
  return true;
}

const FieldDecl *SAGenTestChecker::getMemberFieldDecl(const Expr *E) {
  if (!E)
    return nullptr;
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (const auto *FD = dyn_cast_or_null<FieldDecl>(ME->getMemberDecl()))
      return FD;
  }
  return nullptr;
}

const MemRegion *SAGenTestChecker::getBaseObjectRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C) {
  if (!ME)
    return nullptr;
  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

// True if FD is a flexible-array field and has a counted_by attribute.
// If attribute is present and resolvable, set CounterFD accordingly.
bool SAGenTestChecker::isCountedByFlexibleArrayField(const FieldDecl *FD, const FieldDecl *&CounterFD) {
  CounterFD = nullptr;
  if (!FD)
    return false;

  QualType QT = FD->getType();
  if (!isa<IncompleteArrayType>(QT.getTypePtr()))
    return false;

  // Check for counted_by attribute.
  if (const auto *CBA = FD->getAttr<CountedByAttr>()) {
    // Try to resolve the referenced counter field from the attribute.
    // Clang exposes the expression referencing the counter field.
    if (const Expr *E = CBA->getCountedBy()) {
      E = E->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (const auto *TargetFD = dyn_cast<FieldDecl>(DRE->getDecl())) {
          CounterFD = TargetFD;
        }
      }
      // If we cannot resolve to FieldDecl, still treat as counted_by without CounterFD.
      return true;
    }
    // If attribute exists but no expression, still treat as counted_by.
    return true;
  }

  return false;
}

// Return true if FD is the counter field that a counted_by flexible-array refers to.
bool SAGenTestChecker::isCounterFieldForAnyCountedBy(const FieldDecl *FD) {
  if (!FD)
    return false;
  const RecordDecl *RD = FD->getParent();
  if (!RD)
    return false;

  for (const FieldDecl *F : RD->fields()) {
    const FieldDecl *CntFD = nullptr;
    if (isCountedByFlexibleArrayField(F, CntFD)) {
      if (CntFD && CntFD == FD)
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::reportFlexibleArrayBeforeCounterInit(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "flexible-array used before initializing its __counted_by counter", N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// Track zero-initialized allocations.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
  if (!RetReg)
    return;

  RetReg = RetReg->getBaseRegion();
  if (!RetReg)
    return;

  State = State->add<ZeroedObjs>(RetReg);
  C.addTransition(State);
}

// Mark the counter field as initialized on assignment: obj->counter = ...
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  if (!LHS)
    return;

  const auto *ME = findSpecificTypeInChildren<MemberExpr>(LHS);
  if (!ME)
    return;

  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return;

  if (!isCounterFieldForAnyCountedBy(FD))
    return;

  const MemRegion *BaseR = getBaseObjectRegionFromMemberExpr(ME, C);
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<CounterInitializedObjs>(BaseR);
  C.addTransition(State);
}

// Flag writes into counted_by flexible arrays before counter is initialized.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned DestIdx = 0, LenIdx = 2;
  if (!isMemWriteLike(Call, C, DestIdx, LenIdx))
    return;

  if (Call.getNumArgs() <= DestIdx)
    return;

  const Expr *DstE = Call.getArgExpr(DestIdx);
  if (!DstE)
    return;
  DstE = DstE->IgnoreImpCasts();

  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(DstE);
  if (!ME)
    return;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return;

  const FieldDecl *CounterFD = nullptr;
  if (!isCountedByFlexibleArrayField(FD, CounterFD))
    return;

  const MemRegion *BaseR = getBaseObjectRegionFromMemberExpr(ME, C);
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();

  // Only warn when object is known zero-initialized (typical after kzalloc/kcalloc, etc.).
  if (!State->contains<ZeroedObjs>(BaseR))
    return;

  // If counter already initialized, no issue.
  if (State->contains<CounterInitializedObjs>(BaseR))
    return;

  // Don't warn for zero-length operations.
  if (!isNonZeroLengthArg(Call, LenIdx, C))
    return;

  reportFlexibleArrayBeforeCounterInit(Call.getOriginExpr(), C);
}

// Detect direct stores into the flexible array (e.g., via array subscripts) before counter init.
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (IsLoad)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const MemRegion *Cur = MR;
  // Climb to a FieldRegion if present.
  while (Cur && !isa<FieldRegion>(Cur))
    Cur = Cur->getSuperRegion();

  const auto *FR = dyn_cast_or_null<FieldRegion>(Cur);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  const FieldDecl *CounterFD = nullptr;
  if (!isCountedByFlexibleArrayField(FD, CounterFD))
    return;

  const MemRegion *BaseR = FR->getSuperRegion();
  if (!BaseR)
    return;
  BaseR = BaseR->getBaseRegion();
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();

  if (!State->contains<ZeroedObjs>(BaseR))
    return;

  if (State->contains<CounterInitializedObjs>(BaseR))
    return;

  reportFlexibleArrayBeforeCounterInit(S, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects writes to __counted_by flexible-array before its counter is initialized",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
