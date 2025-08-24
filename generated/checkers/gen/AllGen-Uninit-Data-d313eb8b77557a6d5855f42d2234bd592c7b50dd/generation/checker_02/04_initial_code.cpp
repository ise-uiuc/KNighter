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
#include "clang/AST/Type.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecordLayout.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(StructZeroedMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::PostStmt<DeclStmt>,
    check::PostCall,
    check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Struct copy exposes uninitialized padding", "Security")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      const VarRegion *getBaseVarRegion(const Expr *E, CheckerContext &C) const;
      bool isLocalRecordVar(const VarRegion *VR, CheckerContext &C) const;
      bool isZeroIntegralExpr(const Expr *E, CheckerContext &C) const;
      bool isSizeOfVarOrType(const Expr *LenExpr, const VarRegion *VR, CheckerContext &C) const;
      bool recordHasPadding(QualType QT, ASTContext &ACtx) const;
      ProgramStateRef markZeroed(ProgramStateRef State, const VarRegion *VR) const;
      bool wasZeroed(ProgramStateRef State, const VarRegion *VR) const;
      uint64_t getTypeSizeInBytes(QualType QT, ASTContext &ACtx) const;

      bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) const;
      bool matchCopyToUserLike(const CallEvent &Call, CheckerContext &C,
                               unsigned &SrcIdx, unsigned &LenIdx) const;

      void tryMarkZeroedByMemset(const CallEvent &Call, CheckerContext &C) const;
      void tryReportCopyOutStructPadding(const CallEvent &Call, CheckerContext &C) const;
};

/* Helper implementations */

const VarRegion *SAGenTestChecker::getBaseVarRegion(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return dyn_cast<VarRegion>(MR);
}

bool SAGenTestChecker::isLocalRecordVar(const VarRegion *VR, CheckerContext &C) const {
  if (!VR)
    return false;
  if (!VR->getValueType().isNull() && !VR->getValueType()->isRecordType())
    return false;
  const MemSpaceRegion *MS = VR->getMemorySpace();
  if (!MS)
    return false;
  return isa<StackLocalsSpaceRegion>(MS);
}

bool SAGenTestChecker::isZeroIntegralExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  llvm::APSInt Res;
  if (!EvaluateExprToInt(Res, E, C))
    return false;
  return Res == 0;
}

uint64_t SAGenTestChecker::getTypeSizeInBytes(QualType QT, ASTContext &ACtx) const {
  if (QT.isNull()) return 0;
  return ACtx.getTypeSizeInChars(QT).getQuantity();
}

bool SAGenTestChecker::isSizeOfVarOrType(const Expr *LenExpr, const VarRegion *VR, CheckerContext &C) const {
  if (!LenExpr || !VR) return false;
  const Expr *E = LenExpr->IgnoreParenCasts();
  if (const auto *UETT = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    if (UETT->getKind() != UETT_SizeOf)
      return false;
    if (UETT->isArgumentType()) {
      QualType ArgTy = UETT->getArgumentType().getCanonicalType();
      QualType VarTy = VR->getValueType().getCanonicalType();
      if (ArgTy.isNull() || VarTy.isNull())
        return false;
      return ArgTy == VarTy;
    } else {
      const Expr *AE = UETT->getArgumentExpr();
      if (!AE) return false;
      AE = AE->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(AE)) {
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        if (VD && VD == VR->getDecl())
          return true;
      }
    }
  }
  return false;
}

bool SAGenTestChecker::recordHasPadding(QualType QT, ASTContext &ACtx) const {
  if (QT.isNull())
    return false;
  const RecordType *RT = QT->getAs<RecordType>();
  if (!RT)
    return false;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;
  RD = RD->getDefinition();
  if (!RD)
    return false; // Be conservative: if no definition, don't report.

  const ASTRecordLayout &Layout = ACtx.getASTRecordLayout(RD);
  uint64_t prevEnd = 0;
  unsigned idx = 0;

  for (const FieldDecl *FD : RD->fields()) {
    uint64_t off = Layout.getFieldOffset(idx); // in bits
    if (off > prevEnd)
      return true; // gap before this field
    uint64_t fsize = 0;
    if (FD->isBitField()) {
      fsize = FD->getBitWidthValue(ACtx);
    } else {
      fsize = ACtx.getTypeSize(FD->getType());
    }
    prevEnd = off + fsize;
    ++idx;
  }

  uint64_t totalBits = ACtx.toBits(Layout.getSize());
  if (totalBits > prevEnd)
    return true; // tail padding

  return false;
}

ProgramStateRef SAGenTestChecker::markZeroed(ProgramStateRef State, const VarRegion *VR) const {
  if (!State || !VR) return State;
  return State->set<StructZeroedMap>(VR, true);
}

bool SAGenTestChecker::wasZeroed(ProgramStateRef State, const VarRegion *VR) const {
  if (!State || !VR) return false;
  if (const bool *B = State->get<StructZeroedMap>(VR))
    return *B;
  return false;
}

bool SAGenTestChecker::isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;
  return ExprHasName(OE, Name, C);
}

bool SAGenTestChecker::matchCopyToUserLike(const CallEvent &Call, CheckerContext &C,
                                           unsigned &SrcIdx, unsigned &LenIdx) const {
  // Check more specific names first to avoid substring confusion.
  if (isCallNamed(Call, "nla_put_64bit", C)) {
    SrcIdx = 3; LenIdx = 2; return true;
  }
  if (isCallNamed(Call, "nla_put_nohdr", C)) {
    SrcIdx = 2; LenIdx = 1; return true;
  }
  if (isCallNamed(Call, "nla_put", C)) {
    SrcIdx = 3; LenIdx = 2; return true;
  }
  if (isCallNamed(Call, "copy_to_user", C)) {
    SrcIdx = 1; LenIdx = 2; return true;
  }
  // Add more if needed.
  return false;
}

void SAGenTestChecker::tryMarkZeroedByMemset(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return;

  bool IsMemset = isCallNamed(Call, "memset", C) || isCallNamed(Call, "__builtin_memset", C);
  bool IsBzero  = isCallNamed(Call, "bzero", C);
  if (!IsMemset && !IsBzero)
    return;

  if (Call.getNumArgs() < 2)
    return;

  const MemRegion *DstMR = Call.getArgSVal(0).getAsRegion();
  if (!DstMR)
    return;
  DstMR = DstMR->getBaseRegion();
  const VarRegion *VR = dyn_cast<VarRegion>(DstMR);
  if (!VR)
    return;
  if (!isLocalRecordVar(VR, C))
    return;

  // memset(ptr, 0, len) OR bzero(ptr, len)
  bool ZeroVal = true;
  const Expr *LenExpr = nullptr;

  if (IsMemset) {
    if (Call.getNumArgs() < 3)
      return;
    const Expr *ValExpr = Call.getArgExpr(1);
    if (!isZeroIntegralExpr(ValExpr, C))
      ZeroVal = false;
    LenExpr = Call.getArgExpr(2);
  } else {
    // bzero(ptr, len)
    LenExpr = Call.getArgExpr(1);
  }

  if (!ZeroVal || !LenExpr)
    return;

  bool FullSize = false;
  if (isSizeOfVarOrType(LenExpr, VR, C)) {
    FullSize = true;
  } else {
    llvm::APSInt Res;
    if (EvaluateExprToInt(Res, LenExpr, C)) {
      uint64_t Len = Res.getZExtValue();
      uint64_t TySize = getTypeSizeInBytes(VR->getValueType(), C.getASTContext());
      if (TySize == Len)
        FullSize = true;
    }
  }

  if (!FullSize)
    return;

  State = markZeroed(State, VR);
  C.addTransition(State);
}

void SAGenTestChecker::tryReportCopyOutStructPadding(const CallEvent &Call, CheckerContext &C) const {
  unsigned SrcIdx = 0, LenIdx = 0;
  if (!matchCopyToUserLike(Call, C, SrcIdx, LenIdx))
    return;

  if (Call.getNumArgs() <= std::max(SrcIdx, LenIdx))
    return;

  // Source pointer region
  const MemRegion *SrcMR = Call.getArgSVal(SrcIdx).getAsRegion();
  if (!SrcMR)
    return;
  SrcMR = SrcMR->getBaseRegion();
  const VarRegion *VR = dyn_cast<VarRegion>(SrcMR);
  if (!VR)
    return;
  if (!isLocalRecordVar(VR, C))
    return;

  // Check if length == sizeof(var or type)
  const Expr *LenExpr = Call.getArgExpr(LenIdx);
  bool FullCopy = false;
  if (isSizeOfVarOrType(LenExpr, VR, C)) {
    FullCopy = true;
  } else {
    llvm::APSInt Res;
    if (EvaluateExprToInt(Res, LenExpr, C)) {
      uint64_t Len = Res.getZExtValue();
      uint64_t TySize = getTypeSizeInBytes(VR->getValueType(), C.getASTContext());
      if (TySize == Len)
        FullCopy = true;
    }
  }
  if (!FullCopy)
    return;

  // Check struct has padding
  if (!recordHasPadding(VR->getValueType(), C.getASTContext()))
    return;

  // If not zeroed, report
  ProgramStateRef State = C.getState();
  if (!wasZeroed(State, VR)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Struct with padding copied without full initialization", N);
    R->addRange(Call.getSourceRange());
    if (const Expr *SrcE = Call.getArgExpr(SrcIdx))
      R->addRange(SrcE->getSourceRange());
    if (LenExpr)
      R->addRange(LenExpr->getSourceRange());
    C.emitReport(std::move(R));
  }
}

/* Checker callbacks */

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  MemRegionManager &MRMgr = SVB.getRegionManager();

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->hasLocalStorage())
      continue;

    QualType QT = VD->getType();
    if (QT.isNull() || !QT->isRecordType())
      continue;

    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    const InitListExpr *ILE = dyn_cast<InitListExpr>(Init->IgnoreParenCasts());
    if (!ILE)
      continue;

    // Only accept "{0}" pattern as "fully zeroed".
    bool ZeroInit = false;
    if (ILE->getNumInits() == 1) {
      const Expr *E0 = ILE->getInit(0);
      if (isZeroIntegralExpr(E0, C))
        ZeroInit = true;
    }

    if (!ZeroInit)
      continue;

    const VarRegion *VR = MRMgr.getVarRegion(VD, C.getLocationContext());
    if (!VR)
      continue;
    if (!isLocalRecordVar(VR, C))
      continue;

    State = markZeroed(State, VR);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Detect memset/bzero that fully zero a local struct
  tryMarkZeroedByMemset(Call, C);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Detect copying a whole local struct (with padding) to user space or netlink.
  tryReportCopyOutStructPadding(Call, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects copying a stack struct with padding to user without zeroing the struct",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
