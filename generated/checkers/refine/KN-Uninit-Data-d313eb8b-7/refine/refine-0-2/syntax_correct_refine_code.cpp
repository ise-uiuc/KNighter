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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/AST/RecordLayout.h"
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(PartiallyInitAgg, const VarDecl*, char)
REGISTER_SET_WITH_PROGRAMSTATE(ZeroCleared, const VarDecl*)

// Utility functions provided by the prompt
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {

class SAGenTestChecker : public Checker<
    check::PostStmt<DeclStmt>,
    check::PostCall,
    check::PreCall> {

   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel info leak", "Security")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static const VarDecl *getLocalStructVarFromAddrArg(const Expr *ArgE);
      static bool isZeroBraceInit(const InitListExpr *ILE);
      static bool isNonZeroingInitList(const InitListExpr *ILE);
      static bool sizeofCoversVar(const VarDecl *VD, const Expr *LenExpr, CheckerContext &C);
      static bool isNetlinkExportCall(const CallEvent &Call, unsigned &LenIdx, unsigned &DataIdx, CheckerContext &C);

      enum ZeroKind { ZK_None = 0, ZK_Memset, ZK_MemzeroExplicit, ZK_Bzero };
      static ZeroKind getZeroingKind(const CallEvent &Call, unsigned &PtrIdx, unsigned &LenIdx, CheckerContext &C);

      static bool hasImplicitPadding(QualType QT, ASTContext &Ctx);

      void markZeroCleared(ProgramStateRef &State, const VarDecl *VD) const;
      void markPartiallyInit(ProgramStateRef &State, const VarDecl *VD) const;

      // Additional helpers to eliminate false positives and strengthen matching
      static bool calleeNameIs(const CallEvent &Call, StringRef Name);
      static bool isBraceZeroInitializedVar(const VarDecl *VD);
      static bool isExplicitZeroInitExpr(const Expr *E);
      static bool isFalsePositive(const VarDecl *VD, CheckerContext &C);

      void reportLeak(const CallEvent &Call, CheckerContext &C) const;
};

/************ Helper Implementations ************/

const VarDecl *SAGenTestChecker::getLocalStructVarFromAddrArg(const Expr *ArgE) {
  if (!ArgE) return nullptr;
  const Expr *E = ArgE->IgnoreParenImpCasts();
  const auto *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_AddrOf)
    return nullptr;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return nullptr;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  if (!VD->hasLocalStorage())
    return nullptr;

  if (!VD->getType()->isRecordType())
    return nullptr;

  return VD;
}

bool SAGenTestChecker::isZeroBraceInit(const InitListExpr *ILE) {
  if (!ILE) return false;

  // "{}"
  if (ILE->getNumInits() == 0)
    return true;

  if (ILE->getNumInits() == 1) {
    const Expr *Init = ILE->getInit(0);
    if (!Init) return false;

    // Any designated initializer is considered non-zeroing
    if (isa<DesignatedInitExpr>(Init))
      return false;

    const Expr *E = Init->IgnoreParenImpCasts();
    if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
      if (IL->getValue().isZero())
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isNonZeroingInitList(const InitListExpr *ILE) {
  if (!ILE) return false;
  if (isZeroBraceInit(ILE))
    return false;
  return true;
}

bool SAGenTestChecker::sizeofCoversVar(const VarDecl *VD, const Expr *LenExpr, CheckerContext &C) {
  if (!VD || !LenExpr)
    return false;

  // First attempt: constant evaluation
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, LenExpr, C)) {
    uint64_t LenVal = Res.isSigned() ? (uint64_t)Res.getSExtValue() : Res.getZExtValue();
    uint64_t VarSize = C.getASTContext().getTypeSizeInChars(VD->getType()).getQuantity();
    return LenVal >= VarSize;
  }

  // Fallback: textual containment of sizeof(var) pattern
  if (ExprHasName(LenExpr, "sizeof", C) && ExprHasName(LenExpr, VD->getName(), C))
    return true;

  return false;
}

bool SAGenTestChecker::calleeNameIs(const CallEvent &Call, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  return false;
}

bool SAGenTestChecker::isNetlinkExportCall(const CallEvent &Call, unsigned &LenIdx, unsigned &DataIdx, CheckerContext &C) {
  // Prefer identifier-based matching; fall back to source text as a last resort.
  if (calleeNameIs(Call, "nla_put_64bit") || ExprHasName(Call.getOriginExpr(), "nla_put_64bit", C)) {
    // nla_put_64bit(skb, attrtype, len, data, padtype)
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2;
      DataIdx = 3;
      return true;
    }
    return false;
  }
  if (calleeNameIs(Call, "nla_put") || ExprHasName(Call.getOriginExpr(), "nla_put", C)) {
    // nla_put(skb, attrtype, len, data)
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2;
      DataIdx = 3;
      return true;
    }
    return false;
  }

  return false;
}

SAGenTestChecker::ZeroKind SAGenTestChecker::getZeroingKind(const CallEvent &Call, unsigned &PtrIdx, unsigned &LenIdx, CheckerContext &C) {
  // memset(ptr, 0, len)
  if (calleeNameIs(Call, "memset") || ExprHasName(Call.getOriginExpr(), "memset", C)) {
    if (Call.getNumArgs() >= 3) {
      PtrIdx = 0;
      LenIdx = 2;
      return ZK_Memset;
    }
    return ZK_None;
  }

  // memzero_explicit(ptr, len)
  if (calleeNameIs(Call, "memzero_explicit") || ExprHasName(Call.getOriginExpr(), "memzero_explicit", C)) {
    if (Call.getNumArgs() >= 2) {
      PtrIdx = 0;
      LenIdx = 1;
      return ZK_MemzeroExplicit;
    }
    return ZK_None;
  }

  // bzero(ptr, len)
  if (calleeNameIs(Call, "bzero") || ExprHasName(Call.getOriginExpr(), "bzero", C)) {
    if (Call.getNumArgs() >= 2) {
      PtrIdx = 0;
      LenIdx = 1;
      return ZK_Bzero;
    }
    return ZK_None;
  }

  return ZK_None;
}

// Recursively check if a type (record or arrays of records) has implicit padding.
// This version uses ASTRecordLayout's DataSize vs Size, detects inter-field gaps,
// bitfields, unions, and recurses into nested records and array element types.
static QualType unwrapArrayElementBaseType(QualType T) {
  const Type *Ty = T.getTypePtr();
  while (const auto *AT = dyn_cast<ArrayType>(Ty)) {
    T = cast<ArrayType>(Ty)->getElementType();
    Ty = T.getTypePtr();
  }
  return T;
}

bool SAGenTestChecker::hasImplicitPadding(QualType QT, ASTContext &Ctx) {
  QT = QT.getCanonicalType().getUnqualifiedType();

  // If it's an array, check the base element type.
  if (const auto *AT = dyn_cast<ArrayType>(QT.getTypePtr())) {
    QualType ElemT = unwrapArrayElementBaseType(QT);
    if (ElemT->isRecordType())
      return hasImplicitPadding(ElemT, Ctx);
    return false;
  }

  const RecordType *RT = QT->getAs<RecordType>();
  if (!RT)
    return false;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;

  RD = RD->getDefinition();
  if (!RD)
    return false;

  if (RD->isUnion())
    return true; // conservative for unions

  const ASTRecordLayout &Layout = Ctx.getASTRecordLayout(RD);

  // Inter-field padding and nested record padding
  uint64_t PrevEndBits = 0;
  unsigned Index = 0;

  for (const FieldDecl *FD : RD->fields()) {
    if (FD->isBitField())
      return true;

    QualType FT = FD->getType();
    // Recurse into nested records/array-of-records
    {
      QualType Base = unwrapArrayElementBaseType(FT);
      if (Base->isRecordType() && hasImplicitPadding(Base, Ctx))
        return true;
    }

    uint64_t FieldOffsetBits = Layout.getFieldOffset(Index);
    if (Index > 0 && FieldOffsetBits > PrevEndBits)
      return true; // gap between fields

    uint64_t FieldSizeBits = Ctx.getTypeSize(FT);
    PrevEndBits = FieldOffsetBits + FieldSizeBits;

    ++Index;
  }

  // Tail padding check using DataSize vs Size (more robust than manual sum).
  if (Layout.getSize() > Layout.getDataSize())
    return true;

  return false;
}

void SAGenTestChecker::markZeroCleared(ProgramStateRef &State, const VarDecl *VD) const {
  if (!VD) return;
  State = State->add<ZeroCleared>(VD);
  State = State->remove<PartiallyInitAgg>(VD);
}

void SAGenTestChecker::markPartiallyInit(ProgramStateRef &State, const VarDecl *VD) const {
  if (!VD) return;
  State = State->set<PartiallyInitAgg>(VD, 1);
}

bool SAGenTestChecker::isExplicitZeroInitExpr(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *ILE = dyn_cast<InitListExpr>(E))
    return isZeroBraceInit(ILE);
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue().isZero();
  return false;
}

bool SAGenTestChecker::isBraceZeroInitializedVar(const VarDecl *VD) {
  if (!VD) return false;
  if (!VD->hasInit()) return false;
  const Expr *Init = VD->getInit();
  if (!Init) return false;
  const Expr *I = Init->IgnoreImplicit();
  if (const auto *ILE = dyn_cast<InitListExpr>(I))
    return isZeroBraceInit(ILE);
  // Very defensive: accept a single explicit 0 initializer
  return isExplicitZeroInitExpr(I);
}

bool SAGenTestChecker::isFalsePositive(const VarDecl *VD, CheckerContext &C) {
  // If the var was brace-zero-initialized ("{}" or "{0}"), it's fully zeroed,
  // including padding. Exporting it is safe.
  if (isBraceZeroInitializedVar(VD))
    return true;

  // Path-sensitive knowledge: if we've already marked it zero-cleared (via memset, etc.), it's safe.
  ProgramStateRef State = C.getState();
  if (State->contains<ZeroCleared>(VD))
    return true;

  return false;
}

/************ Checker Callbacks ************/

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS) return;
  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!VD->hasLocalStorage())
      continue;

    if (!VD->getType()->isRecordType())
      continue;

    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    const Expr *I = Init->IgnoreImplicit();
    const auto *ILE = dyn_cast<InitListExpr>(I);
    if (!ILE) {
      // If not an init-list, still record if it's equivalent to zero-init.
      if (isExplicitZeroInitExpr(I)) {
        ProgramStateRef NewState = State->add<ZeroCleared>(VD);
        if (NewState != State) { State = NewState; Changed = true; }
      }
      continue;
    }

    // If zero-brace init, mark cleared regardless of padding.
    if (isZeroBraceInit(ILE)) {
      ProgramStateRef NewState = State->add<ZeroCleared>(VD);
      if (NewState != State) {
        State = NewState;
        Changed = true;
      }
      continue;
    }

    // Only interesting if the type actually has implicit padding.
    if (isNonZeroingInitList(ILE) &&
        hasImplicitPadding(VD->getType(), C.getASTContext())) {
      ProgramStateRef NewState = State->set<PartiallyInitAgg>(VD, 1);
      if (NewState != State) {
        State = NewState;
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  unsigned PtrIdx = 0, LenIdx = 0;
  ZeroKind ZK = getZeroingKind(Call, PtrIdx, LenIdx, C);
  if (ZK == ZK_None)
    return;

  // Identify the variable being cleared
  const Expr *PtrE = Call.getArgExpr(PtrIdx);
  const Expr *LenE = Call.getArgExpr(LenIdx);
  const VarDecl *VD = getLocalStructVarFromAddrArg(PtrE);
  if (!VD)
    return;

  // For memset, the "value" argument must be zero
  if (ZK == ZK_Memset) {
    const Expr *ValE = Call.getArgExpr(1);
    llvm::APSInt V;
    if (!ValE || !EvaluateExprToInt(V, ValE, C) || !V.isZero())
      return;
  }

  // Ensure len covers the entire variable
  if (!sizeofCoversVar(VD, LenE, C))
    return;

  // Mark as zero-cleared and remove partial-init flag
  State = State->add<ZeroCleared>(VD);
  State = State->remove<PartiallyInitAgg>(VD);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned LenIdx = 0, DataIdx = 0;
  if (!isNetlinkExportCall(Call, LenIdx, DataIdx, C))
    return;

  const Expr *DataE = Call.getArgExpr(DataIdx);
  const Expr *LenE = Call.getArgExpr(LenIdx);
  const VarDecl *VD = getLocalStructVarFromAddrArg(DataE);
  if (!VD)
    return;

  if (!sizeofCoversVar(VD, LenE, C))
    return;

  // If the record type has no implicit padding/holes, exporting it cannot leak
  // uninitialized padding bytes. Do not warn.
  if (!hasImplicitPadding(VD->getType(), C.getASTContext()))
    return;

  // Eliminate false positives where the aggregate is brace-zero-initialized
  // (or otherwise known zeroed).
  if (isFalsePositive(VD, C))
    return;

  ProgramStateRef State = C.getState();

  // Warn only if we have evidence of risky partial init via init-list.
  if (!State->get<PartiallyInitAgg>(VD))
    return;

  reportLeak(Call, C);
}

void SAGenTestChecker::reportLeak(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Copying partially initialized struct with padding to user; zero-initialize before export", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects exporting partially initialized padded structs without zeroing (kernel info leak)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
