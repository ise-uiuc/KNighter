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
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallVector.h"
#include <utility>
#include <algorithm>
#include <climits>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructs, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)

namespace {

class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::PostCall,
        check::PreCall> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Kernel info leak: copying stack struct with padding",
                       "Security")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helpers
  const VarRegion *resolveBaseStructVarRegion(const Expr *PtrArg,
                                              CheckerContext &C) const;
  bool lenMatchesStructSize(const Expr *LenArg, QualType StructTy,
                            CheckerContext &C) const;
  bool recordHasImplicitPadding(const RecordDecl *RD,
                                ASTContext &AC) const;
  bool isZeroingCall(const CallEvent &Call,
                     unsigned &PtrIdx, unsigned &ValIdx, unsigned &LenIdx,
                     bool &ValueIsZero, bool &NeedValueCheck,
                     CheckerContext &C) const;
  bool isCopyOutCall(const CallEvent &Call,
                     unsigned &LenIdx, unsigned &PtrIdx,
                     CheckerContext &C) const;
};

// Return the base VarRegion of a local struct variable that PtrArg refers to,
// optionally via a pointer alias. Returns nullptr if not resolvable.
const VarRegion *SAGenTestChecker::resolveBaseStructVarRegion(const Expr *PtrArg,
                                                              CheckerContext &C) const {
  if (!PtrArg)
    return nullptr;

  const MemRegion *R = getMemRegionFromExpr(PtrArg, C);
  if (!R)
    return nullptr;

  R = R->getBaseRegion();
  if (!R)
    return nullptr;

  ProgramStateRef State = C.getState();

  // If R is a VarRegion, check if it is a local struct variable directly.
  if (const auto *VR = dyn_cast<VarRegion>(R)) {
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      return nullptr;

    if (VD->isLocalVarDecl() && !VD->hasGlobalStorage()) {
      QualType QT = VD->getType();
      if (const RecordType *RT = QT->getAs<RecordType>()) {
        if (const RecordDecl *RD = dyn_cast_or_null<RecordDecl>(RT->getDecl())) {
          if (RD->isStruct())
            return VR;
        }
      }
    }

    // If it's a local pointer var, try alias map.
    if (VD->getType()->isPointerType()) {
      if (const MemRegion *const *AliasedPtr = State->get<PtrAliasMap>(VR)) {
        const MemRegion *Aliased = *AliasedPtr;
        if (const auto *AliasedVR = dyn_cast_or_null<VarRegion>(Aliased)) {
          const VarDecl *AVD = AliasedVR->getDecl();
          if (!AVD)
            return nullptr;
          if (AVD->isLocalVarDecl() && !AVD->hasGlobalStorage()) {
            QualType QT = AVD->getType();
            if (const RecordType *RT = QT->getAs<RecordType>()) {
              if (const RecordDecl *RD = dyn_cast_or_null<RecordDecl>(RT->getDecl())) {
                if (RD->isStruct())
                  return AliasedVR;
              }
            }
          }
        }
      }
    }
  }

  // Not a direct VarRegion or couldn't resolve to a struct var.
  return nullptr;
}

// Check if LenArg equals sizeof(StructTy).
bool SAGenTestChecker::lenMatchesStructSize(const Expr *LenArg,
                                            QualType StructTy,
                                            CheckerContext &C) const {
  if (!LenArg)
    return false;

  ASTContext &AC = C.getASTContext();
  QualType CanonStructTy = AC.getCanonicalType(StructTy);

  const Expr *LE = LenArg->IgnoreParenCasts();
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(LE)) {
    if (U->getKind() == UETT_SizeOf) {
      QualType SizeofTy;
      if (U->isArgumentType())
        SizeofTy = U->getArgumentType();
      else if (const Expr *ArgE = U->getArgumentExpr())
        SizeofTy = ArgE->getType();

      if (!SizeofTy.isNull()) {
        QualType CanonSizeofTy = AC.getCanonicalType(SizeofTy);
        if (AC.hasSameUnqualifiedType(CanonSizeofTy, CanonStructTy))
          return true;
      }
    }
  }

  // Fallback: evaluate LenArg to int and compare to size in bytes.
  llvm::APSInt LenVal;
  if (EvaluateExprToInt(LenVal, LenArg, C)) {
    uint64_t Len = LenVal.getZExtValue();
    uint64_t StructSize = AC.getTypeSizeInChars(StructTy).getQuantity();
    return Len == StructSize;
  }

  return false;
}

// Determine whether a record has implicit padding (interior or trailing).
bool SAGenTestChecker::recordHasImplicitPadding(const RecordDecl *RD,
                                                ASTContext &AC) const {
  if (!RD)
    return false;
  if (!RD->isStruct())
    return false;
  RD = RD->getDefinition();
  if (!RD)
    return false;

  const ASTRecordLayout &L = AC.getASTRecordLayout(RD);

  uint64_t LastEndBits = 0;
  unsigned Index = 0;
  for (const FieldDecl *FD : RD->fields()) {
    if (!FD)
      continue;
    uint64_t FieldOffsetBits = L.getFieldOffset(Index);
    uint64_t FieldSizeBits = AC.getTypeSize(FD->getType());
    if (FieldOffsetBits > LastEndBits)
      return true; // interior padding
    LastEndBits = FieldOffsetBits + FieldSizeBits;
    ++Index;
  }

  uint64_t TotalBits = L.getSize().getQuantity() * 8ULL;
  if (TotalBits > LastEndBits)
    return true; // trailing padding

  return false;
}

// Identify zeroing calls. Returns true and fills indices if recognized.
// For memset/__builtin_memset: PtrIdx=0, ValIdx=1, LenIdx=2, NeedValueCheck=true, ValueIsZero if value is proven zero.
// For memzero_explicit: PtrIdx=0, LenIdx=1, NeedValueCheck=false (implicitly zero).
// For bzero: PtrIdx=0, LenIdx=1, NeedValueCheck=false (implicitly zero).
bool SAGenTestChecker::isZeroingCall(const CallEvent &Call,
                                     unsigned &PtrIdx, unsigned &ValIdx, unsigned &LenIdx,
                                     bool &ValueIsZero, bool &NeedValueCheck,
                                     CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  if (ExprHasName(Origin, "memset", C) ||
      ExprHasName(Origin, "__builtin_memset", C)) {
    if (Call.getNumArgs() < 3)
      return false;
    PtrIdx = 0; ValIdx = 1; LenIdx = 2;
    NeedValueCheck = true;
    ValueIsZero = false;
    return true;
  }

  if (ExprHasName(Origin, "memzero_explicit", C)) {
    if (Call.getNumArgs() < 2)
      return false;
    PtrIdx = 0; LenIdx = 1;
    NeedValueCheck = false;
    ValueIsZero = true;
    ValIdx = UINT_MAX;
    return true;
  }

  if (ExprHasName(Origin, "bzero", C)) {
    if (Call.getNumArgs() < 2)
      return false;
    PtrIdx = 0; LenIdx = 1;
    NeedValueCheck = false;
    ValueIsZero = true;
    ValIdx = UINT_MAX;
    return true;
  }

  return false;
}

// Identify copy-out functions to user space or netlink, and provide indices.
bool SAGenTestChecker::isCopyOutCall(const CallEvent &Call,
                                     unsigned &LenIdx, unsigned &PtrIdx,
                                     CheckerContext &C) const {
  struct CopySig { const char *Name; unsigned Len; unsigned Ptr; };
  static const CopySig Table[] = {
      {"nla_put", 2, 3},
      {"nla_put_64bit", 2, 3},
      {"nla_put_nohdr", 1, 2},
      {"copy_to_user", 2, 1},
      {"copy_to_user_nofault", 2, 1},
      {"copy_to_iter", 2, 1},
  };

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  for (const auto &E : Table) {
    if (ExprHasName(Origin, E.Name, C)) {
      if (Call.getNumArgs() <= std::max(E.Len, E.Ptr))
        return false;
      LenIdx = E.Len;
      PtrIdx = E.Ptr;
      return true;
    }
  }
  return false;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSR = Loc.getAsRegion();
  if (!LHSR)
    return;
  LHSR = LHSR->getBaseRegion();
  if (!LHSR)
    return;

  const auto *LHSVR = dyn_cast<VarRegion>(LHSR);
  if (!LHSVR)
    return;

  const VarDecl *LHSVD = LHSVR->getDecl();
  if (!LHSVD)
    return;
  if (!LHSVD->getType()->isPointerType())
    return; // Track only pointer variables on LHS

  const MemRegion *RHSR = Val.getAsRegion();
  if (!RHSR)
    return;
  RHSR = RHSR->getBaseRegion();
  if (!RHSR)
    return;

  // Case 1: RHS is another pointer var with an existing alias
  if (const auto *RHSVR = dyn_cast<VarRegion>(RHSR)) {
    const VarDecl *RHSVD = RHSVR->getDecl();
    if (!RHSVD)
      return;

    // If RHS is a pointer variable with an alias mapping, propagate it.
    if (RHSVD->getType()->isPointerType()) {
      if (const MemRegion *const *AliasedPtr = State->get<PtrAliasMap>(RHSVR)) {
        const MemRegion *Aliased = *AliasedPtr;
        State = State->set<PtrAliasMap>(LHSVR, Aliased);
        C.addTransition(State);
        return;
      }
    }

    // Case 2: RHS is a local struct variable (taking its address assigned to LHS)
    if (RHSVD->isLocalVarDecl() && !RHSVD->hasGlobalStorage()) {
      QualType QT = RHSVD->getType();
      if (const RecordType *RT = QT->getAs<RecordType>()) {
        if (const RecordDecl *RD = dyn_cast_or_null<RecordDecl>(RT->getDecl())) {
          if (RD->isStruct()) {
            State = State->set<PtrAliasMap>(LHSVR, RHSVR);
            C.addTransition(State);
            return;
          }
        }
      }
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  unsigned PtrIdx = 0, ValIdx = 0, LenIdx = 0;
  bool ValueIsZero = false, NeedValueCheck = false;

  if (!isZeroingCall(Call, PtrIdx, ValIdx, LenIdx, ValueIsZero, NeedValueCheck, C))
    return;

  // Check value is zero for memset variants that require it.
  if (NeedValueCheck) {
    const Expr *ValE = Call.getArgExpr(ValIdx);
    if (!ValE)
      return;
    llvm::APSInt V;
    if (!EvaluateExprToInt(V, ValE, C))
      return;
    if (!V.isNullValue())
      return; // Not zeroing
    ValueIsZero = true;
  }

  if (!ValueIsZero)
    return;

  // Resolve target struct var region
  const Expr *PtrE = Call.getArgExpr(PtrIdx);
  if (!PtrE)
    return;
  const VarRegion *VR = resolveBaseStructVarRegion(PtrE, C);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return;

  QualType StructTy = VD->getType();
  if (!StructTy->isRecordType())
    return;

  // Size check: ensure full-object zeroing
  const Expr *LenE = Call.getArgExpr(LenIdx);
  if (!lenMatchesStructSize(LenE, StructTy, C))
    return;

  // Mark as fully zeroed
  State = State->set<ZeroedStructs>(VR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  unsigned LenIdx = 0, PtrIdx = 0;
  if (!isCopyOutCall(Call, LenIdx, PtrIdx, C))
    return;

  const Expr *PtrE = Call.getArgExpr(PtrIdx);
  const Expr *LenE = Call.getArgExpr(LenIdx);
  if (!PtrE || !LenE)
    return;

  const VarRegion *VR = resolveBaseStructVarRegion(PtrE, C);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return;
  if (!(VD->isLocalVarDecl() && !VD->hasGlobalStorage()))
    return;

  QualType StructTy = VD->getType();
  const RecordType *RT = StructTy->getAs<RecordType>();
  if (!RT)
    return;
  const RecordDecl *RD = dyn_cast_or_null<RecordDecl>(RT->getDecl());
  if (!RD || !RD->isStruct())
    return;

  // Verify length matches sizeof(struct)
  if (!lenMatchesStructSize(LenE, StructTy, C))
    return;

  // Verify the struct layout has implicit padding
  if (!recordHasImplicitPadding(RD, C.getASTContext()))
    return;

  // If not marked as zeroed, report
  const bool *Zeroed = State->get<ZeroedStructs>(VR);
  if (!Zeroed || *Zeroed == false) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Stack struct with padding copied with sizeof; missing zero-init (info leak)", N);
    if (const Stmt *S = Call.getOriginExpr())
      R->addRange(S->getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects copying of partially initialized stack structs with padding to user space (info leak)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
