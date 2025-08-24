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
#include "clang/AST/Decl.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks local struct variables that have been fully zeroed by memset/bzero.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructMap, const MemRegion*, bool)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker()
     : BT(new BugType(this,
                      "Kernel infoleak: copying stack struct with uninitialized padding",
                      "Security")) {}

   void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
   void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
   // Helpers
   static bool isZeroingFunc(const CallEvent &Call, CheckerContext &C);
   static bool isNLAPutLike(const CallEvent &Call, CheckerContext &C);
   static bool pickNlaArgsIndices(const CallEvent &Call, CheckerContext &C,
                                  unsigned &LenIdx, unsigned &DataIdx);

   static const VarDecl* getAddrOfLocalVar(const Expr *E, CheckerContext &C,
                                           const MemRegion* &OutRegion);

   static bool tryEvalToUnsigned(const Expr *E, CheckerContext &C, uint64_t &Out);
   static uint64_t getTypeSizeInBytes(QualType QT, CheckerContext &C);
   static bool recordHasPadding(QualType QT, CheckerContext &C);
};

// Return true if the call is memset/__builtin_memset/bzero
bool SAGenTestChecker::isZeroingFunc(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  if (ExprHasName(OE, "memset", C))
    return true;
  if (ExprHasName(OE, "__builtin_memset", C))
    return true;
  if (ExprHasName(OE, "bzero", C))
    return true;
  return false;
}

// Return true if the call is one of nla_put-like functions we care about.
bool SAGenTestChecker::isNLAPutLike(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, "nla_put", C) ||
         ExprHasName(OE, "nla_put_64bit", C) ||
         ExprHasName(OE, "nla_put_nohdr", C) ||
         ExprHasName(OE, "nla_put_with_pad", C);
}

// Determine argument indices for len and data for nla_put-like calls.
bool SAGenTestChecker::pickNlaArgsIndices(const CallEvent &Call, CheckerContext &C,
                                          unsigned &LenIdx, unsigned &DataIdx) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  if (ExprHasName(OE, "nla_put_nohdr", C)) {
    // nla_put_nohdr(skb, len, data)
    if (Call.getNumArgs() < 3)
      return false;
    LenIdx = 1;
    DataIdx = 2;
    return true;
  }

  if (ExprHasName(OE, "nla_put", C) ||
      ExprHasName(OE, "nla_put_64bit", C) ||
      ExprHasName(OE, "nla_put_with_pad", C)) {
    // nla_put*(skb, type, len, data, ...)
    if (Call.getNumArgs() < 4)
      return false;
    LenIdx = 2;
    DataIdx = 3;
    return true;
  }

  return false;
}

// If E is &localVar, return the VarDecl and its MemRegion (base region).
const VarDecl* SAGenTestChecker::getAddrOfLocalVar(const Expr *E, CheckerContext &C,
                                                   const MemRegion* &OutRegion) {
  OutRegion = nullptr;
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();
  const auto *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_AddrOf)
    return nullptr;

  const Expr *Sub = UO->getSubExpr();
  if (!Sub)
    return nullptr;

  Sub = Sub->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return nullptr;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  // Only consider local variables (stack-allocated in function scope).
  if (!VD->hasLocalStorage())
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(DRE, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;

  OutRegion = MR;
  return VD;
}

bool SAGenTestChecker::tryEvalToUnsigned(const Expr *E, CheckerContext &C, uint64_t &Out) {
  if (!E)
    return false;
  llvm::APSInt V;
  if (!EvaluateExprToInt(V, E, C))
    return false;
  Out = V.getZExtValue();
  return true;
}

uint64_t SAGenTestChecker::getTypeSizeInBytes(QualType QT, CheckerContext &C) {
  return C.getASTContext().getTypeSizeInChars(QT).getQuantity();
}

// Determine if a struct type has internal padding or tail padding.
bool SAGenTestChecker::recordHasPadding(QualType QT, CheckerContext &C) {
  QT = QT.getCanonicalType();
  if (!QT->isStructureType())
    return false;

  const auto *RT = QT->getAs<RecordType>();
  if (!RT)
    return false;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;
  if (RD->isUnion())
    return false;
  if (!RD->isCompleteDefinition())
    return false;

  ASTContext &Ctx = C.getASTContext();
  const ASTRecordLayout &Layout = Ctx.getASTRecordLayout(RD);

  uint64_t PrevEndBits = 0;
  unsigned Index = 0;
  for (const FieldDecl *FD : RD->fields()) {
    if (!FD)
      continue;

    // If this is a flexible array member at end, stop checking here.
    // We conservatively ignore it for padding calculation.
    if (FD->getType()->isIncompleteArrayType())
      break;

    uint64_t FieldOffsetBits = Layout.getFieldOffset(Index);
    uint64_t FieldSizeBits = 0;

    if (FD->isBitField()) {
      // Bit-field width in bits
      FieldSizeBits = FD->getBitWidthValue(Ctx);
    } else {
      FieldSizeBits = Ctx.getTypeSize(FD->getType()); // in bits
    }

    if (FieldOffsetBits > PrevEndBits) {
      // Gap detected -> internal padding
      return true;
    }

    uint64_t EndBits = FieldOffsetBits + FieldSizeBits;
    if (EndBits > PrevEndBits)
      PrevEndBits = EndBits;

    ++Index;
  }

  // Tail padding: struct size (including alignment) > end of last field.
  uint64_t RecordSizeBits = Ctx.getTypeSize(QT); // in bits
  if (RecordSizeBits > PrevEndBits)
    return true;

  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isZeroingFunc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return;

  // memset(dst, value, size)
  if (ExprHasName(OE, "memset", C) || ExprHasName(OE, "__builtin_memset", C)) {
    if (Call.getNumArgs() < 3)
      return;

    const MemRegion *MR = nullptr;
    const VarDecl *VD = getAddrOfLocalVar(Call.getArgExpr(0), C, MR);
    if (!VD || !MR)
      return;

    // value must be 0
    uint64_t ValU = 0;
    if (!tryEvalToUnsigned(Call.getArgExpr(1), C, ValU))
      return;
    if (ValU != 0)
      return;

    // size must cover the whole struct
    uint64_t SizeU = 0;
    if (!tryEvalToUnsigned(Call.getArgExpr(2), C, SizeU))
      return;

    uint64_t TypeSize = getTypeSizeInBytes(VD->getType(), C);
    if (SizeU >= TypeSize) {
      State = State->set<ZeroedStructMap>(MR, true);
      C.addTransition(State);
    }
    return;
  }

  // bzero(dst, size)
  if (ExprHasName(OE, "bzero", C)) {
    if (Call.getNumArgs() < 2)
      return;

    const MemRegion *MR = nullptr;
    const VarDecl *VD = getAddrOfLocalVar(Call.getArgExpr(0), C, MR);
    if (!VD || !MR)
      return;

    uint64_t SizeU = 0;
    if (!tryEvalToUnsigned(Call.getArgExpr(1), C, SizeU))
      return;

    uint64_t TypeSize = getTypeSizeInBytes(VD->getType(), C);
    if (SizeU >= TypeSize) {
      State = State->set<ZeroedStructMap>(MR, true);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isNLAPutLike(Call, C))
    return;

  unsigned LenIdx = 0, DataIdx = 0;
  if (!pickNlaArgsIndices(Call, C, LenIdx, DataIdx))
    return;

  if (Call.getNumArgs() <= std::max(LenIdx, DataIdx))
    return;

  // Data argument must be &localStructVar
  const MemRegion *MR = nullptr;
  const VarDecl *VD = getAddrOfLocalVar(Call.getArgExpr(DataIdx), C, MR);
  if (!VD || !MR)
    return;

  QualType VarQT = VD->getType();
  if (!VarQT->isStructureType())
    return;

  if (!recordHasPadding(VarQT, C))
    return;

  // len must be exactly sizeof(var)
  uint64_t LenU = 0;
  if (!tryEvalToUnsigned(Call.getArgExpr(LenIdx), C, LenU))
    return;

  uint64_t TypeSize = getTypeSizeInBytes(VarQT, C);
  if (LenU != TypeSize)
    return;

  // If explicitly zeroed before, consider safe.
  ProgramStateRef State = C.getState();
  const bool *Zeroed = State->get<ZeroedStructMap>(MR);
  if (Zeroed && *Zeroed)
    return;

  // Report: copying stack struct with padding directly to user space
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Copying stack struct with uninitialized padding; zero it before nla_put",
      N);
  const Expr *DataE = Call.getArgExpr(DataIdx);
  if (DataE)
    R->addRange(DataE->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect copying stack struct with padding to user via nla_put without zeroing",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
