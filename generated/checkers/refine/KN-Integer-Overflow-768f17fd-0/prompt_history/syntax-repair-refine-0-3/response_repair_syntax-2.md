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
#include "clang/StaticAnalyzer/Core/PathSensitive/Store.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "llvm/ADT/StringRef.h"
#include <algorithm>
#include <memory>
#include <utility>

using namespace clang;
using namespace ento;
using namespace clang::ento::taint;

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

// Track variables that effectively carry 32-bit register data even if their C type is 64-bit.
REGISTER_SET_WITH_PROGRAMSTATE(Reg32Vars, const MemRegion *)

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
                                   CheckerContext &C, StringRef Ctx,
                                   const MemRegion *DestRegion = nullptr) const;

  static const BinaryOperator *findShiftInTree(const Stmt *S);
  static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);

  // Helpers
  static const Expr *peel(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  static unsigned getTypeWidth(QualType T, ASTContext &ACtx) {
    return T.isNull() ? 0u : ACtx.getTypeSize(T);
  }

  static bool isIntegerTypeWidthAtMost(QualType T, ASTContext &ACtx, unsigned W) {
    return T->isIntegerType() && getTypeWidth(T, ACtx) <= W;
  }

  static bool isIntegerTypeWidthAtLeast(QualType T, ASTContext &ACtx, unsigned W) {
    return T->isIntegerType() && getTypeWidth(T, ACtx) >= W;
  }

  static bool isNonLiteralExpr(const Expr *E) {
    if (!E) return false;
    E = E->IgnoreParenImpCasts();
    return !isa<IntegerLiteral>(E);
  }

  // Heuristic: recognize "likely 32-bit hardware read" expressions.
  // Return true if E has integer type width <= 32 and is not a plain integer literal,
  // and is one of: a function call, a DeclRefExpr/MemberExpr to <=32-bit data.
  static bool isLikelyNarrowHardwareRead(const Expr *E, CheckerContext &C) {
    if (!E) return false;
    ASTContext &ACtx = C.getASTContext();
    QualType QT = E->getType();
    if (!isIntegerTypeWidthAtMost(QT, ACtx, 32))
      return false;

    E = E->IgnoreParenImpCasts();
    if (isa<IntegerLiteral>(E))
      return false;

    if (isa<CallExpr>(E))
      return true;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      const ValueDecl *VD = DRE->getDecl();
      if (VD && isIntegerTypeWidthAtMost(VD->getType(), ACtx, 32))
        return true;
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const ValueDecl *VD = ME->getMemberDecl())
        if (isIntegerTypeWidthAtMost(VD->getType(), ACtx, 32))
          return true;
    }

    return false;
  }

  // If both LHS and RHS are constants and the shift result fits into LHS width, suppress.
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

  // Centralized FP gate
  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     CheckerContext &C) {
    // Suppress if the shift isn't the top-level expression being assigned/returned/passed.
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    return false;
  }

  // Get MemRegion of LHS expression (variable) if any.
  static const MemRegion *getDestRegionFromLHS(const Expr *LHS, CheckerContext &C) {
    if (!LHS) return nullptr;
    return getMemRegionFromExpr(LHS, C);
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
    if (ToTy->isIntegerType() && getTypeWidth(ToTy, ACtx) >= 64)
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
                                                   CheckerContext &C, StringRef /*Ctx*/,
                                                   const MemRegion *DestRegion) const {
  if (!E)
    return;

  ASTContext &ACtx = C.getASTContext();

  if (!DestTy->isIntegerType())
    return;

  unsigned DestW = getTypeWidth(DestTy, ACtx);
  if (DestW < 64)
    return;

  // If the destination region is known to hold only 32-bit register values, suppress.
  if (DestRegion) {
    ProgramStateRef State = C.getState();
    const Reg32VarsTy &Set = State->get<Reg32Vars>();
    if (Set.contains(DestRegion))
      return;
  }

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

  unsigned ShlW = getTypeWidth(ShlTy, ACtx);
  if (ShlW >= 64)
    return; // Shift already performed in 64-bit, OK.

  // LHS must be integer and narrower than 64.
  if (!L->getType()->isIntegerType())
    return;

  unsigned LHSW = getTypeWidth(L->getType(), ACtx);
  if (LHSW >= 64)
    return; // LHS is already wide enough.

  // If there is an explicit cast to >=64-bit within the LHS subtree, suppress.
  if (hasExplicitCastToWide64(L, ACtx))
    return;

  // Suppress known false-positive contexts (non top-level shift).
  if (isFalsePositiveContext(E, Shl, C))
    return;

  // Precise constant-bound suppression: only if both sides are constants and safe.
  if (constantShiftFitsInLHSWidth(L, R, LHSW, C))
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

  ProgramStateRef State = C.getState();
  ASTContext &ACtx = C.getASTContext();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    // If there's an initializer, analyze and also update Reg32 tracking.
    if (VD->hasInit()) {
      const Expr *Init = VD->getInit();
      QualType DestTy = VD->getType();

      // Try to get the region for this variable for both analysis and tracking.
      const MemRegion *DestReg = nullptr;
      {
        MemRegionManager &MRMgr = C.getStoreManager().getRegionManager();
        const VarRegion *VR = MRMgr.getVarRegion(VD, C.getLocationContext());
        DestReg = VR;
      }

      // Update Reg32 tracking on initialization: only mark when the initializer
      // looks like a register read (<=32-bit, non-literal).
      if (isIntegerTypeWidthAtLeast(DestTy, ACtx, 64) &&
          isLikelyNarrowHardwareRead(Init, C) && DestReg) {
        State = State->add<Reg32Vars>(DestReg);
        C.addTransition(State);
      }

      // Analyze for potential bug; pass DestReg for FP suppression based on Reg32 tracking.
      analyzeAndReportShiftToWide(Init, DestTy, C, "initialization", DestReg);
    }
  }
}

void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  ASTContext &ACtx = C.getASTContext();

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType DestTy = LHS->getType();
  const MemRegion *DestReg = getDestRegionFromLHS(LHS, C);

  // Update Reg32 tracking for simple assignments: mark/unmark as needed.
  if (BO->getOpcode() == BO_Assign && DestReg) {
    ProgramStateRef State = C.getState();

    // Mark as Reg32 if assigning from a likely <=32-bit hardware read expr.
    if (isIntegerTypeWidthAtLeast(DestTy, ACtx, 64) &&
        isLikelyNarrowHardwareRead(RHS, C)) {
      State = State->add<Reg32Vars>(DestReg);
      C.addTransition(State);
    } else {
      // If assigning a >=64-bit value, unmark.
      if (isIntegerTypeWidthAtLeast(RHS->getType(), ACtx, 64)) {
        State = State->remove<Reg32Vars>(DestReg);
        C.addTransition(State);
      }
    }
  }

  // Analyze RHS for potential bug; pass DestReg to enable Reg32 suppression.
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment", DestReg);
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
  analyzeAndReportShiftToWide(RetE, DestTy, C, "return", /*DestRegion=*/nullptr);
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

    analyzeAndReportShiftToWide(ArgE, DestTy, C, "argument", /*DestRegion=*/nullptr);
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
