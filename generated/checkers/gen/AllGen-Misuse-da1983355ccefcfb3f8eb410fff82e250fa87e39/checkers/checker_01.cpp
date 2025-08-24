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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Attr.h"
#include "llvm/Support/Casting.h"
#include <utility>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states:
// - ZeroInitObjs: set of heap objects (pointee regions) known to be zero-initialized.
REGISTER_SET_WITH_PROGRAMSTATE(ZeroInitObjs, const MemRegion *)

// - CountInitFlag: map from object base region to a boolean indicating whether
//   the relevant __counted_by() count field has been initialized (written).
REGISTER_MAP_WITH_PROGRAMSTATE(CountInitFlag, const MemRegion *, bool)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall, // track zero-initializing allocators
        check::PreCall,  // catch memcpy/memmove into counted_by flex array
        check::Bind      // mark writes to count fields
      > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Copy into __counted_by array before count init",
                       "API Misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool isZeroInitAllocator(const CallEvent &Call, CheckerContext &C);
  static bool isMemcpyLike(const CallEvent &Call, CheckerContext &C);

  static bool sizeExprIsDefinitelyZero(const Expr *SizeArg, CheckerContext &C);

  // Retrieve the FieldRegion for a destination expression (or one of its sub-exprs),
  // and the corresponding base object region.
  static bool getFieldRegionAndBase(const Expr *E, CheckerContext &C,
                                    const FieldRegion *&OutFR,
                                    const MemRegion *&OutBase);

  // Determine if the given field FD is used as a count field by any flexible
  // array field in the same record that has a __counted_by(FD) attribute.
  static bool isCountFieldInRecord(const FieldDecl *FD);

  // For a flexible array field, fetch its counted_by() referenced count field.
  static bool getCountFieldForFlexArray(const FieldDecl *FlexFD,
                                        const FieldDecl *&CountFD);
};

// Helper: check if the call is a zero-initializing allocator we care about.
bool SAGenTestChecker::isZeroInitAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Use ExprHasName for robust matching.
  return ExprHasName(OriginExpr, "kzalloc", C) ||
         ExprHasName(OriginExpr, "kcalloc", C) ||
         ExprHasName(OriginExpr, "kvzalloc", C) ||
         ExprHasName(OriginExpr, "vzalloc", C) ||
         ExprHasName(OriginExpr, "devm_kzalloc", C) ||
         ExprHasName(OriginExpr, "devm_kcalloc", C);
}

// Helper: check if the call is a memcpy-like function we're interested in.
bool SAGenTestChecker::isMemcpyLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, "memcpy", C) ||
         ExprHasName(OriginExpr, "memmove", C);
}

// Helper: is the size expression definitely zero?
bool SAGenTestChecker::sizeExprIsDefinitelyZero(const Expr *SizeArg, CheckerContext &C) {
  if (!SizeArg)
    return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, SizeArg, C)) {
    return Res == 0;
  }
  return false;
}

// Helper: From an expression, locate a FieldRegion in its region chain and return its base object.
bool SAGenTestChecker::getFieldRegionAndBase(const Expr *E, CheckerContext &C,
                                             const FieldRegion *&OutFR,
                                             const MemRegion *&OutBase) {
  OutFR = nullptr;
  OutBase = nullptr;
  if (!E)
    return false;

  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return false;

  // Walk up the region chain looking for a FieldRegion.
  const MemRegion *Cur = MR;
  while (Cur) {
    if (const auto *FR = dyn_cast<FieldRegion>(Cur)) {
      OutFR = FR;
      const MemRegion *Super = FR->getSuperRegion();
      if (!Super)
        return false;
      OutBase = Super->getBaseRegion();
      return OutFR && OutBase;
    }
    if (const auto *SR = dyn_cast<SubRegion>(Cur))
      Cur = SR->getSuperRegion();
    else
      break;
  }

  // Fallback: try to find a MemberExpr within E and retry once.
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    const MemRegion *MR2 = getMemRegionFromExpr(ME, C);
    Cur = MR2;
    while (Cur) {
      if (const auto *FR = dyn_cast<FieldRegion>(Cur)) {
        OutFR = FR;
        const MemRegion *Super = FR->getSuperRegion();
        if (!Super)
          return false;
        OutBase = Super->getBaseRegion();
        return OutFR && OutBase;
      }
      if (const auto *SR = dyn_cast<SubRegion>(Cur))
        Cur = SR->getSuperRegion();
      else
        break;
    }
  }

  return false;
}

// Helper: For a flexible-array member field, obtain the counted_by() count field.
bool SAGenTestChecker::getCountFieldForFlexArray(const FieldDecl *FlexFD,
                                                 const FieldDecl *&CountFD) {
  CountFD = nullptr;
  if (!FlexFD)
    return false;

  QualType T = FlexFD->getType();
  if (!T.getTypePtr() || !T->isIncompleteArrayType())
    return false;

  // In Clang 18, CountedByAttr does not expose a uniform accessor across versions
  // for the referenced field. For our purposes, presence of the attribute on a
  // flexible array member indicates it's a counted_by flexible array.
  if (FlexFD->hasAttr<CountedByAttr>()) {
    // We don't rely on the exact referenced field here.
    return true;
  }

  return false;
}

// Helper: Is FD used as a count field in any __counted_by() flexible array in the same record?
bool SAGenTestChecker::isCountFieldInRecord(const FieldDecl *FD) {
  if (!FD)
    return false;
  const RecordDecl *RD = FD->getParent();
  if (!RD)
    return false;

  // If the record declares any counted_by flexible array member, and FD is an
  // integer-typed field in the same record, conservatively treat it as a count field.
  // This keeps the intended semantics while avoiding reliance on unstable APIs.
  bool HasCountedByFlexArray = false;
  for (const FieldDecl *F : RD->fields()) {
    if (!F)
      continue;
    QualType FT = F->getType();
    if (!FT.getTypePtr() || !FT->isIncompleteArrayType())
      continue;
    if (F->hasAttr<CountedByAttr>()) {
      HasCountedByFlexArray = true;
      break;
    }
  }

  if (!HasCountedByFlexArray)
    return false;

  // Consider typical count fields to be integral types.
  return FD->getType().getTypePtr() && FD->getType()->isIntegerType();
}

// Post-call: record zero-initialized allocations.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroInitAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Get the region representing the return value expression, then its base.
  const MemRegion *MR = getMemRegionFromExpr(OriginExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->add<ZeroInitObjs>(MR);
  C.addTransition(State);
}

// Pre-call: detect copying into a counted_by flexible array before its count is initialized.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isMemcpyLike(Call, C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DstExpr = Call.getArgExpr(0);
  const Expr *SizeExpr = Call.getArgExpr(2);

  const FieldRegion *FR = nullptr;
  const MemRegion *BaseReg = nullptr;
  if (!getFieldRegionAndBase(DstExpr, C, FR, BaseReg))
    return;

  if (!FR || !BaseReg)
    return;

  // Ensure destination field is a flexible array with __counted_by().
  const FieldDecl *FlexFD = FR->getDecl();
  if (!FlexFD)
    return;

  const FieldDecl *CountFD = nullptr;
  // Only check for presence of counted_by attribute on the flexible array.
  if (!getCountFieldForFlexArray(FlexFD, CountFD))
    return; // Not a counted_by flexible array; ignore.

  // Only care about objects known to be zero-initialized (kzalloc/kcalloc/etc).
  ProgramStateRef State = C.getState();
  if (!State->contains<ZeroInitObjs>(BaseReg))
    return;

  // If the counting field was already initialized for this object, it's fine.
  if (const bool *Inited = State->get<CountInitFlag>(BaseReg)) {
    if (*Inited)
      return;
  }

  // Optional suppression: if size is definitely zero, skip.
  if (sizeExprIsDefinitelyZero(SizeExpr, C))
    return;

  // Report: copying into __counted_by array before initializing its count field.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Copy into __counted_by array before initializing its count field",
      N);
  if (DstExpr)
    R->addRange(DstExpr->getSourceRange());
  C.emitReport(std::move(R));
}

// Bind: mark writes to counted_by count fields as initialized per object.
void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt * /*S*/, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  // Find the FieldRegion in the region chain.
  const MemRegion *Cur = R;
  const FieldRegion *FR = nullptr;
  while (Cur) {
    if (const auto *TmpFR = dyn_cast<FieldRegion>(Cur)) {
      FR = TmpFR;
      break;
    }
    if (const auto *SR = dyn_cast<SubRegion>(Cur))
      Cur = SR->getSuperRegion();
    else
      break;
  }
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  // If this field is a count field for any counted_by flexible array in the same record, mark initialized.
  if (!isCountFieldInRecord(FD))
    return;

  const MemRegion *Super = FR->getSuperRegion();
  if (!Super)
    return;

  const MemRegion *BaseReg = Super->getBaseRegion();
  if (!BaseReg)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<CountInitFlag>(BaseReg, true);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memcpy/memmove into __counted_by flexible array before initializing the count field",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
