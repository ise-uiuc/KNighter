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
      auto BoundToPtr = State->get<SizeBoundMap>(CountReg);
      if (BoundToPtr && (*BoundToPtr)->getBaseRegion() == BufReg)
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
    if (EvalRes.isUnsigned() || EvalRes.isNonNegative()) {
      uint64_t CountVal = EvalRes.isUnsigned()
                              ? EvalRes.getZExtValue()
                              : static_cast<uint64_t>(EvalRes.getSExtValue());
      uint64_t ArraySize = ArraySizeBits.getZExtValue();
      if (CountVal <= ArraySize)
        return; // safe
      // If CountVal definitely exceeds ArraySize, report.
      // Note: copying exactly sizeof(buf) bytes is acceptable for raw bytes.
      // We'll treat strictly greater than array size as unsafe.
      if (CountVal > ArraySize) {
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
        auto BoundToPtr = State->get<SizeBoundMap>(RHSReg);
        if (BoundToPtr) {
          State = State->set<SizeBoundMap>(LHSReg, (*BoundToPtr)->getBaseRegion());
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
