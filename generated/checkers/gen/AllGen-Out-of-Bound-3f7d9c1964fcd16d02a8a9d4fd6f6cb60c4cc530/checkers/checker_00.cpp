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
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables/fields that hold a device-provided size (rss_max_key_size).
REGISTER_SET_WITH_PROGRAMSTATE(DeviceSizeSet, const MemRegion*)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker< check::Bind, check::PreCall > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unbounded device-provided RSS key length used", "Memory Safety")) {}

      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      // Helpers
      bool isVirtioCreadOfRssKeySize(const CallEvent &Call, CheckerContext &C) const;
      bool isVirtioCreadOfRssKeySize(const CallExpr *CE, CheckerContext &C) const;

      bool isKnownCopyLenSink(const CallEvent &Call, unsigned &DestIdx, unsigned &LenIdx, CheckerContext &C) const;

      const MemRegion* resolveExprRegion(const Expr *E, CheckerContext &C) const;

      bool lenComesFromDeviceSize(const Expr *LenE, CheckerContext &C) const;

      bool getConstArraySizeOfExpr(llvm::APInt &ArraySize, const Expr *DestE, CheckerContext &C) const;

      bool lengthIsProvablyBounded(CheckerContext &C, const Expr *LenE, uint64_t Limit) const;

      void report(const CallEvent &Call, const Expr *LenE, CheckerContext &C) const;
};

bool SAGenTestChecker::isVirtioCreadOfRssKeySize(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Match function name virtio_cread8/16/32
  bool IsCread =
      ExprHasName(Origin, "virtio_cread8", C) ||
      ExprHasName(Origin, "virtio_cread16", C) ||
      ExprHasName(Origin, "virtio_cread32", C);
  if (!IsCread)
    return false;

  if (Call.getNumArgs() < 2)
    return false;

  const Expr *OffsetExpr = Call.getArgExpr(1);
  if (!OffsetExpr)
    return false;

  // The offset expression should contain "rss_max_key_size"
  return ExprHasName(OffsetExpr, "rss_max_key_size", C);
}

bool SAGenTestChecker::isVirtioCreadOfRssKeySize(const CallExpr *CE, CheckerContext &C) const {
  if (!CE)
    return false;

  // Check callee name using source text
  if (!(ExprHasName(CE, "virtio_cread8", C) ||
        ExprHasName(CE, "virtio_cread16", C) ||
        ExprHasName(CE, "virtio_cread32", C)))
    return false;

  if (CE->getNumArgs() < 2)
    return false;

  const Expr *OffsetExpr = CE->getArg(1);
  if (!OffsetExpr)
    return false;

  return ExprHasName(OffsetExpr, "rss_max_key_size", C);
}

bool SAGenTestChecker::isKnownCopyLenSink(const CallEvent &Call, unsigned &DestIdx, unsigned &LenIdx, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // memcpy(dest, src, len)
  if (ExprHasName(Origin, "memcpy", C)) {
    if (Call.getNumArgs() >= 3) {
      DestIdx = 0;
      LenIdx = 2;
      return true;
    }
    return false;
  }

  // memmove(dest, src, len)
  if (ExprHasName(Origin, "memmove", C)) {
    if (Call.getNumArgs() >= 3) {
      DestIdx = 0;
      LenIdx = 2;
      return true;
    }
    return false;
  }

  // virtio_cread_bytes(dev, off, buf, len)
  if (ExprHasName(Origin, "virtio_cread_bytes", C)) {
    if (Call.getNumArgs() >= 4) {
      DestIdx = 2;
      LenIdx = 3;
      return true;
    }
    return false;
  }

  return false;
}

const MemRegion* SAGenTestChecker::resolveExprRegion(const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (MR) {
    MR = MR->getBaseRegion();
    return MR;
  }

  // Try find a DeclRefExpr child
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(E)) {
    MR = getMemRegionFromExpr(DRE, C);
    if (MR) {
      MR = MR->getBaseRegion();
      return MR;
    }
  }

  // Try find a MemberExpr child
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    MR = getMemRegionFromExpr(ME, C);
    if (MR) {
      MR = MR->getBaseRegion();
      return MR;
    }
  }

  return nullptr;
}

bool SAGenTestChecker::lenComesFromDeviceSize(const Expr *LenE, CheckerContext &C) const {
  if (!LenE)
    return false;

  // Case 1: direct call to virtio_creadX(..., rss_max_key_size)
  if (const auto *CE = dyn_cast<CallExpr>(LenE->IgnoreParenCasts())) {
    if (isVirtioCreadOfRssKeySize(CE, C))
      return true;
  }

  // Case 2: variable/field previously marked as device size
  if (const MemRegion *MR = resolveExprRegion(LenE, C)) {
    ProgramStateRef State = C.getState();
    if (State->contains<DeviceSizeSet>(MR))
      return true;
  }

  return false;
}

bool SAGenTestChecker::getConstArraySizeOfExpr(llvm::APInt &ArraySize, const Expr *DestE, CheckerContext &C) const {
  if (!DestE)
    return false;

  // First try the provided helper on the expression directly.
  if (getArraySizeFromExpr(ArraySize, DestE))
    return true;

  // Check if the expression type itself is a constant array.
  QualType QT = DestE->getType();
  if (!QT.isNull()) {
    if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
      ArraySize = CAT->getSize();
      return true;
    }
  }

  // Try DeclRefExpr child
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(DestE)) {
    if (getArraySizeFromExpr(ArraySize, DRE))
      return true;

    // Also try type of the referenced declaration
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType VDTy = VD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(VDTy.getTypePtr())) {
        ArraySize = CAT->getSize();
        return true;
      }
    }
  }

  // Try MemberExpr child: get the FieldDecl type
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(DestE)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      QualType FTy = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(FTy.getTypePtr())) {
        ArraySize = CAT->getSize();
        return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::lengthIsProvablyBounded(CheckerContext &C, const Expr *LenE, uint64_t Limit) const {
  if (!LenE)
    return false;

  ProgramStateRef State = C.getState();
  SVal LenSVal = State->getSVal(LenE, C.getLocationContext());
  if (SymbolRef Sym = LenSVal.getAsSymbol()) {
    if (const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C)) {
      // If we can infer a maximum and it's <= Limit, it's safe
      uint64_t MaxZ = Max->getZExtValue();
      return MaxZ <= Limit;
    }
  }
  return false;
}

void SAGenTestChecker::report(const CallEvent &Call, const Expr *LenE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unbounded device-provided RSS key length used", N);

  if (LenE)
    R->addRange(LenE->getSourceRange());
  if (const Expr *OE = Call.getOriginExpr())
    R->addRange(OE->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (LHSReg)
    LHSReg = LHSReg->getBaseRegion();

  // Propagate tag on simple assignments: if RHS region is in set, add LHS
  if (LHSReg) {
    if (const MemRegion *RHSReg = Val.getAsRegion()) {
      RHSReg = RHSReg->getBaseRegion();
      if (RHSReg && State->contains<DeviceSizeSet>(RHSReg)) {
        State = State->add<DeviceSizeSet>(LHSReg);
        C.addTransition(State);
        return;
      }
    }
  }

  // If RHS is a call to virtio_cread{8,16,32}(..., rss_max_key_size), mark LHS
  if (LHSReg && S) {
    // Find a CallExpr under this statement (assignment RHS)
    if (const auto *CE = findSpecificTypeInChildren<CallExpr>(S)) {
      if (isVirtioCreadOfRssKeySize(CE, C)) {
        State = State->add<DeviceSizeSet>(LHSReg);
        C.addTransition(State);
        return;
      }
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned DestIdx = 0, LenIdx = 0;
  if (!isKnownCopyLenSink(Call, DestIdx, LenIdx, C))
    return;

  const Expr *LenE = Call.getArgExpr(LenIdx);
  if (!lenComesFromDeviceSize(LenE, C))
    return;

  // Determine destination capacity
  const Expr *DestE = Call.getArgExpr(DestIdx);
  llvm::APInt ArrSize;
  if (!getConstArraySizeOfExpr(ArrSize, DestE, C))
    return; // Can't prove destination capacity; avoid false positives

  uint64_t Capacity = ArrSize.getZExtValue();
  if (lengthIsProvablyBounded(C, LenE, Capacity))
    return; // Proved safe on this path

  // Report: device-provided rss key length used without bound check
  report(Call, LenE, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded device-provided RSS key length usage in copy-like APIs",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
