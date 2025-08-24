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
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/APSInt.h"
#include <cstdint>
#include <algorithm>
#include <memory>
#include <optional>

// Additional includes for region/type queries
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
// 0 = Unknown/not tracked, 1 = Zeroed allocation (kzalloc/kcalloc), 2 = Possibly-uninitialized (kmalloc/*)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocKindMap, const MemRegion*, unsigned)
// Records last known zero-initialized byte size via memset/memzero_explicit for the base region.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitSizeMap, const MemRegion*, uint64_t)
// Tracks pointer aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
// Tracks producer-initialized buffers: buffer -> symbol of length value after producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerLenSymMap, const MemRegion*, SymbolRef)
// Tracks producer-initialized buffers: buffer -> symbol of status/return value of producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerStatusSymMap, const MemRegion*, SymbolRef)
// Tracks a conservative contiguous initialized prefix (in bytes) from the start of the region.
REGISTER_MAP_WITH_PROGRAMSTATE(InitPrefixMap, const MemRegion*, uint64_t)
// Counts the number of distinct write operations observed into the region (heuristic for structured init).
REGISTER_MAP_WITH_PROGRAMSTATE(WriteCountMap, const MemRegion*, unsigned)
// Tracks the last write length as a symbol for the destination buffer (e.g., memcpy_fromio/memcpy when non-constant).
REGISTER_MAP_WITH_PROGRAMSTATE(LastWriteLenSymMap, const MemRegion*, SymbolRef)
// Tracks the last write destination offset (in bytes) from the base region.
REGISTER_MAP_WITH_PROGRAMSTATE(LastWriteOffsetMap, const MemRegion*, uint64_t)

// New state to correlate memcpy len symbol with an accumulator used in copy_to_user.
// Map: length SymbolRef used in last memcpy -> kmalloc base region written
REGISTER_MAP_WITH_PROGRAMSTATE(LenSymToBaseMap, SymbolRef, const MemRegion*)
// Map: kmalloc base region -> accumulator variable region (the integer that accumulates copied bytes)
REGISTER_MAP_WITH_PROGRAMSTATE(AccumLenVarForBaseMap, const MemRegion*, const MemRegion*)

// Utility function declarations (provided externally in the prompt)
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
extern llvm::SmallVector<KnownDerefFunction, 16> DerefTable;
bool functionKnownToDeref(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {
class SAGenTestChecker : public Checker<
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel information leak", "Security")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      const MemRegion *canonical(ProgramStateRef State, const MemRegion *R) const;
      ProgramStateRef setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const;
      bool callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const;
      const MemRegion *getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      const MemRegion *getPointeeRegionForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      void noteExplicitInitLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIndex, unsigned LenArgIndex) const;
      void reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const;

      // Producer modeling helpers
      bool functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const;
      bool functionKnownToInitLenIsReturn(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx) const;
      SymbolRef getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      bool isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const;

      // New initialization tracking helpers
      void markBytesWrittenToRegion(const MemRegion *SubR, uint64_t Len, CheckerContext &C) const;
      void tryRecordDirectStore(const MemRegion *StoreR, CheckerContext &C) const;
      bool getRegionOffsetAndBase(const MemRegion *R, const MemRegion *&Base, uint64_t &ByteOffset) const;
      uint64_t getTypeSizeInBytes(QualType T, ASTContext &ASTC) const;
      void noteWriteCallWithLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIdx, unsigned LenArgIdx) const;

      // Additional helpers for symbol-based suppression
      void recordSymbolicWrite(const MemRegion *DstR, SymbolRef LenSym, std::optional<uint64_t> OffsetOpt, CheckerContext &C) const;
      bool suppressDueToLastWriteSymbol(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const;

      // New FP suppression for memcpy-accumulate-copy_to_user pattern
      bool suppressDueToAccumulatorPattern(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const;
};

const MemRegion *SAGenTestChecker::canonical(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return nullptr;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return nullptr;

  const MemRegion *Cur = Base;
  for (unsigned i = 0; i < 8; ++i) {
    if (const MemRegion *const *NextP = State->get<PtrAliasMap>(Cur)) {
      const MemRegion *Next = *NextP;
      if (Next == Cur)
        break;
      Cur = Next->getBaseRegion();
      continue;
    }
    break;
  }
  return Cur;
}

ProgramStateRef SAGenTestChecker::setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const {
  if (!R)
    return State;
  R = R->getBaseRegion();
  if (!R)
    return State;
  const MemRegion *Canon = canonical(State, R);
  if (!Canon)
    return State;
  State = State->set<AllocKindMap>(Canon, Kind);
  // Reset any previous explicit-init info; a fresh allocation supersedes it.
  State = State->remove<ZeroInitSizeMap>(Canon);
  // Clear producer-derived initialization info to avoid stale mapping across re-allocations.
  State = State->remove<ProducerLenSymMap>(Canon);
  State = State->remove<ProducerStatusSymMap>(Canon);
  // Clear observed write/initialized-prefix tracking.
  State = State->remove<InitPrefixMap>(Canon);
  State = State->remove<WriteCountMap>(Canon);
  // Clear last-write symbol-based info.
  State = State->remove<LastWriteLenSymMap>(Canon);
  State = State->remove<LastWriteOffsetMap>(Canon);
  // Clear accumulator related info.
  State = State->remove<AccumLenVarForBaseMap>(Canon);
  return State;
}

bool SAGenTestChecker::callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

const MemRegion *SAGenTestChecker::getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  const Expr *ArgE = Call.getArgExpr(Idx);
  const MemRegion *MR = nullptr;
  if (ArgE)
    MR = getMemRegionFromExpr(ArgE, C);
  if (!MR) {
    SVal V = Call.getArgSVal(Idx);
    MR = V.getAsRegion();
  }
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;
  ProgramStateRef State = C.getState();
  return canonical(State, MR);
}

// Return the pointee region for a pointer argument to a call.
const MemRegion *SAGenTestChecker::getPointeeRegionForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  const Expr *ArgE = Call.getArgExpr(Idx);
  ProgramStateRef State = C.getState();

  // Prefer using the expression path to get the runtime value region.
  if (ArgE) {
    SVal ArgSV = State->getSVal(ArgE, C.getLocationContext());
    if (const MemRegion *AsRegion = ArgSV.getAsRegion()) {
      // If this is already a pointee region (MemRegionVal), return it.
      // Otherwise, if this is a region of the pointer variable, read its value.
      if (isa<SubRegion>(AsRegion) || isa<SymbolicRegion>(AsRegion)) {
        return AsRegion;
      } else {
        SValBuilder &SVB = C.getSValBuilder();
        Loc PtrLoc = SVB.makeLoc(AsRegion);
        SVal PointeeV = State->getSVal(PtrLoc);
        if (const MemRegion *PointeeR = PointeeV.getAsRegion())
          return PointeeR;
      }
    }
  }

  // Fallback through SVal
  SVal PtrSV = Call.getArgSVal(Idx);
  if (const MemRegion *PtrR = PtrSV.getAsRegion()) {
    SValBuilder &SVB = C.getSValBuilder();
    Loc PtrLoc = SVB.makeLoc(PtrR);
    SVal PointeeV = State->getSVal(PtrLoc);
    if (const MemRegion *PointeeR = PointeeV.getAsRegion())
      return PointeeR;
  }

  return nullptr;
}

uint64_t SAGenTestChecker::getTypeSizeInBytes(QualType T, ASTContext &ASTC) const {
  if (T.isNull())
    return 0;
  // Incomplete or variable-length types might return 0.
  if (T->isIncompleteType())
    return 0;
  CharUnits CU = ASTC.getTypeSizeInChars(T);
  if (CU.isNegative())
    return 0;
  return (uint64_t)CU.getQuantity();
}

void SAGenTestChecker::noteExplicitInitLen(const CallEvent &Call, CheckerContext &C,
                                           unsigned PtrArgIndex, unsigned LenArgIndex) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = getPointeeRegionForPointerArg(Call, PtrArgIndex, C);
  if (!DstReg)
    return;

  DstReg = DstReg->getBaseRegion();
  DstReg = canonical(State, DstReg);
  if (!DstReg)
    return;

  const Expr *LenE = Call.getArgExpr(LenArgIndex);
  if (!LenE)
    return;

  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, LenE, C))
    return;

  uint64_t Len = EvalRes.getZExtValue();
  const uint64_t *Old = State->get<ZeroInitSizeMap>(DstReg);
  uint64_t NewLen = Old ? std::max(*Old, Len) : Len;
  State = State->set<ZeroInitSizeMap>(DstReg, NewLen);

  // Also treat this as generic initialization coverage.
  const uint64_t *OldP = State->get<InitPrefixMap>(DstReg);
  uint64_t NewP = OldP ? std::max(*OldP, Len) : Len;
  State = State->set<InitPrefixMap>(DstReg, NewP);

  // Clear producer symbols
  State = State->remove<ProducerLenSymMap>(DstReg);
  State = State->remove<ProducerStatusSymMap>(DstReg);

  // Reset last-write symbol tracking to avoid stale matches.
  State = State->remove<LastWriteLenSymMap>(DstReg);
  State = State->remove<LastWriteOffsetMap>(DstReg);

  C.addTransition(State);
}

void SAGenTestChecker::reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

// Recognize known producer that fills an output buffer up to length returned in len-pointer on success.
bool SAGenTestChecker::functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const {
  if (const Expr *Origin = Call.getOriginExpr()) {
    if (ExprHasName(Origin, "get_variable", C)) {
      if (Call.getNumArgs() >= 5) {
        BufParamIdx = 4;
        LenPtrParamIdx = 3;
        return true;
      }
    }
  }
  return false;
}

// Recognize producers that return the number of bytes initialized in the buffer.
bool SAGenTestChecker::functionKnownToInitLenIsReturn(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx) const {
  if (const Expr *Origin = Call.getOriginExpr()) {
    // usb_control_msg(dev, pipe, req, reqtype, value, index, data, size, timeout)
    if (ExprHasName(Origin, "usb_control_msg", C)) {
      if (Call.getNumArgs() >= 9) {
        BufParamIdx = 6;
        return true;
      }
    }
    // asym_eds_op(params, in, out): return value is number of bytes written or < 0 on error.
    if (ExprHasName(Origin, "asym_eds_op", C)) {
      if (Call.getNumArgs() >= 3) {
        BufParamIdx = 2; // 'out' buffer
        return true;
      }
    }
  }
  return false;
}

SymbolRef SAGenTestChecker::getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SVal PtrV = Call.getArgSVal(Idx);
  const MemRegion *PtrReg = PtrV.getAsRegion();
  if (!PtrReg)
    return nullptr;
  SValBuilder &SVB = C.getSValBuilder();
  Loc L = SVB.makeLoc(PtrReg);
  SVal Pointee = State->getSVal(L);
  return Pointee.getAsSymbol();
}

// Decide if this copy_to_user should be suppressed because a known producer
// fully initialized the buffer for exactly the number of bytes being copied.
bool SAGenTestChecker::isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const {
  ProgramStateRef State = C.getState();

  const SymbolRef *LenSymP = State->get<ProducerLenSymMap>(FromReg);
  if (!LenSymP || !*LenSymP)
    return false;

  SVal LenArgV = CopyToUserCall.getArgSVal(2);
  SymbolRef CopyLenSym = LenArgV.getAsSymbol();
  if (!CopyLenSym || CopyLenSym != *LenSymP)
    return false;

  if (const SymbolRef *StatusSymP = State->get<ProducerStatusSymMap>(FromReg)) {
    if (*StatusSymP) {
      SValBuilder &SVB = C.getSValBuilder();
      QualType IntTy = C.getASTContext().IntTy;
      DefinedOrUnknownSVal Cond = SVB.evalEQ(State,
                                             nonloc::SymbolVal(*StatusSymP),
                                             SVB.makeZeroVal(IntTy));
      if (auto StTrue = State->assume(Cond, true)) {
        auto StFalse = State->assume(Cond, false);
        if (StTrue && !StFalse) {
          return true;
        }
      }
    }
  }

  return true;
}

// Compute offset to base and base region for a subregion.
// Returns true only if a concrete byte offset is known; returns false otherwise.
bool SAGenTestChecker::getRegionOffsetAndBase(const MemRegion *R, const MemRegion *&Base, uint64_t &ByteOffset) const {
  if (!R)
    return false;

  // For explicit subregions try to compute concrete offset.
  if (const auto *SR = dyn_cast<SubRegion>(R)) {
    std::optional<RegionOffset> RO = SR->getAsOffset();
    if (!RO.has_value())
      return false;
    Base = RO->getRegion();
    int64_t BitOff = RO->getOffset();
    if (BitOff < 0)
      return false;
    if ((uint64_t)BitOff % 8 != 0)
      return false; // ignore bitfield or non-byte aligned
    ByteOffset = (uint64_t)BitOff / 8;
    return true;
  }

  // If it's not a SubRegion but is the base object itself, treat as offset 0.
  const MemRegion *B = R->getBaseRegion();
  if (B && B == R) {
    Base = B;
    ByteOffset = 0;
    return true;
  }

  return false;
}

// Record that [Offset, Offset+Len) bytes in the base region have been written,
// and update the contiguous initialized prefix if applicable. Also increments a write count.
void SAGenTestChecker::markBytesWrittenToRegion(const MemRegion *SubR, uint64_t Len, CheckerContext &C) const {
  if (!SubR || Len == 0)
    return;
  ProgramStateRef State = C.getState();

  const MemRegion *Base = nullptr;
  uint64_t Off = 0;
  if (!getRegionOffsetAndBase(SubR, Base, Off))
    return;

  const MemRegion *CanonBase = canonical(State, Base ? Base->getBaseRegion() : nullptr);
  if (!CanonBase)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(CanonBase);
  if (!Kind || *Kind != 2) // only track possibly-uninitialized kmalloc regions
    return;

  const uint64_t *OldP = State->get<InitPrefixMap>(CanonBase);
  uint64_t Prefix = OldP ? *OldP : 0;

  if (Off <= Prefix) {
    uint64_t NewEnd = Off + Len;
    if (NewEnd > Prefix) {
      State = State->set<InitPrefixMap>(CanonBase, NewEnd);
    }
  }

  const unsigned *OldCnt = State->get<WriteCountMap>(CanonBase);
  unsigned NewCnt = OldCnt ? (*OldCnt + 1) : 1u;
  State = State->set<WriteCountMap>(CanonBase, NewCnt);

  // This concrete-length write supersedes any symbolic last-write info.
  State = State->remove<LastWriteLenSymMap>(CanonBase);
  State = State->remove<LastWriteOffsetMap>(CanonBase);

  C.addTransition(State);
}

// Record symbolic writes for functions like memcpy/memmove/memcpy_fromio/copy_from_user.
// We increment write-count for the base, and only record a last offset if it is concretely known.
void SAGenTestChecker::recordSymbolicWrite(const MemRegion *DstR, SymbolRef LenSym, std::optional<uint64_t> OffsetOpt, CheckerContext &C) const {
  if (!DstR || !LenSym)
    return;

  ProgramStateRef State = C.getState();

  // Identify base region even if offset is unknown.
  const MemRegion *BaseR = DstR->getBaseRegion();
  const MemRegion *CanonBase = canonical(State, BaseR);
  if (!CanonBase)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(CanonBase);
  if (!Kind || *Kind != 2)
    return;

  // Increment write count
  const unsigned *OldCnt = State->get<WriteCountMap>(CanonBase);
  unsigned NewCnt = OldCnt ? (*OldCnt + 1) : 1u;
  State = State->set<WriteCountMap>(CanonBase, NewCnt);

  // Record last write len sym; record offset only if known.
  State = State->set<LastWriteLenSymMap>(CanonBase, LenSym);
  if (OffsetOpt.has_value())
    State = State->set<LastWriteOffsetMap>(CanonBase, *OffsetOpt);
  else
    State = State->remove<LastWriteOffsetMap>(CanonBase);

  // Remember that this length symbol was used to write into this base.
  State = State->set<LenSymToBaseMap>(LenSym, CanonBase);

  C.addTransition(State);
}

// Note a write-by-call pattern like memcpy/memmove/memcpy_fromio/copy_from_user where len is provided explicitly.
void SAGenTestChecker::noteWriteCallWithLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIdx, unsigned LenArgIdx) const {
  // Get destination pointee region of the write (not the pointer variable itself).
  const MemRegion *DstPointeeR = getPointeeRegionForPointerArg(Call, PtrArgIdx, C);
  if (!DstPointeeR)
    return;

  // Try constant evaluation first.
  const Expr *LenE = Call.getArgExpr(LenArgIdx);
  bool Recorded = false;
  if (LenE) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, LenE, C)) {
      uint64_t Len = EvalRes.getZExtValue();
      if (Len != 0) {
        markBytesWrittenToRegion(DstPointeeR, Len, C);
        Recorded = true;
      }
    }
  }

  if (Recorded)
    return;

  // Fall back to symbol-based recording.
  SVal LenSV = Call.getArgSVal(LenArgIdx);
  if (SymbolRef LenSym = LenSV.getAsSymbol()) {
    // Try to compute concrete offset if possible.
    const MemRegion *Base = nullptr;
    uint64_t Off = 0;
    std::optional<uint64_t> OffsetOpt;
    if (getRegionOffsetAndBase(DstPointeeR, Base, Off))
      OffsetOpt = Off;

    recordSymbolicWrite(DstPointeeR, LenSym, OffsetOpt, C);
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Allocation modeling
  if (callNamed(Call, C, "kzalloc") || callNamed(Call, C, "kcalloc")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 1);
        C.addTransition(State);
      }
    }
    return;
  }

  if (callNamed(Call, C, "kmalloc") || callNamed(Call, C, "kmalloc_array") || callNamed(Call, C, "kmalloc_node")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 2);
        C.addTransition(State);
      }
    }
    return;
  }

  // Explicit initialization modeling
  if (callNamed(Call, C, "memset")) {
    // memset(ptr, val, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/2);
    return;
  }

  if (callNamed(Call, C, "memzero_explicit")) {
    // memzero_explicit(ptr, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/1);
    return;
  }

  // Treat memcpy/memmove as generic initialization of destination (not zeroed).
  if (callNamed(Call, C, "memcpy") || callNamed(Call, C, "memmove")) {
    // memcpy(dst, src, len)
    noteWriteCallWithLen(Call, C, /*PtrArgIdx=*/0, /*LenArgIdx=*/2);
    return;
  }

  // Model memcpy_fromio(dst, src_io, len) as destination initialization.
  if (callNamed(Call, C, "memcpy_fromio")) {
    noteWriteCallWithLen(Call, C, /*PtrArgIdx=*/0, /*LenArgIdx=*/2);
    return;
  }

  // Model copy_from_user(dst, src, len) as destination initialization.
  if (callNamed(Call, C, "copy_from_user")) {
    noteWriteCallWithLen(Call, C, /*PtrArgIdx=*/0, /*LenArgIdx=*/2);
    return;
  }

  // Some wrappers may still appear as direct calls; be permissive for bacpy if not inlined.
  if (callNamed(Call, C, "bacpy")) {
    // bacpy(dst, src) - usually memcpy of 6 bytes; we can't get the size here if not inlined.
    // Skip if we cannot evaluate size; most kernels inline bacpy to memcpy so above path handles it.
  }

  // Producer initialization modeling (len via out-pointer)
  unsigned BufIdx = 0, LenPtrIdx = 0;
  if (functionKnownToInitBuffer(Call, C, BufIdx, LenPtrIdx)) {
    const MemRegion *BufReg = getArgBaseRegion(Call, BufIdx, C);
    if (BufReg) {
      SymbolRef LenSym = getPointeeSymbolForPointerArg(Call, LenPtrIdx, C);
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (LenSym && RetSym) {
        State = State->set<ProducerLenSymMap>(BufReg, LenSym);
        State = State->set<ProducerStatusSymMap>(BufReg, RetSym);
        C.addTransition(State);
      }
    }
    return;
  }

  // Producer initialization modeling (len is return value)
  unsigned RetLenBufIdx = 0;
  if (functionKnownToInitLenIsReturn(Call, C, RetLenBufIdx)) {
    const MemRegion *BufReg = getArgBaseRegion(Call, RetLenBufIdx, C);
    if (BufReg) {
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (RetSym) {
        State = State->set<ProducerLenSymMap>(BufReg, RetSym);
        // No separate status symbol for this API; clear any previous status.
        State = State->remove<ProducerStatusSymMap>(BufReg);
        C.addTransition(State);
      }
    }
    return;
  }
}

// Suppress false positives when the last write into the buffer used the same length symbol as copy_to_user and started at offset 0.
bool SAGenTestChecker::suppressDueToLastWriteSymbol(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const {
  ProgramStateRef State = C.getState();

  const SymbolRef *LastLenSymP = State->get<LastWriteLenSymMap>(FromReg);
  const uint64_t *LastOffP = State->get<LastWriteOffsetMap>(FromReg);
  if (!LastLenSymP || !*LastLenSymP || !LastOffP)
    return false;

  if (*LastOffP != 0)
    return false; // Only trust writes that start at base offset 0.

  SVal CopyLenV = CopyToUserCall.getArgSVal(2);
  SymbolRef CopyLenSym = CopyLenV.getAsSymbol();
  if (!CopyLenSym)
    return false;

  return (CopyLenSym == *LastLenSymP);
}

// Suppress when we have seen memcpy(..., lenSym) into this base, immediately followed by "<accum> += lenSym",
// and copy_to_user length is exactly that <accum> variable.
bool SAGenTestChecker::suppressDueToAccumulatorPattern(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const {
  ProgramStateRef State = C.getState();

  // copy_to_user(to, from, len)
  const Expr *LenE = CopyToUserCall.getArgExpr(2);
  if (!LenE)
    return false;

  // The length should be a variable region (e.g., "bytes_copied").
  const MemRegion *LenVarReg = getMemRegionFromExpr(LenE, C);
  if (!LenVarReg)
    return false;
  LenVarReg = LenVarReg->getBaseRegion();

  const MemRegion *const *AccumVarP = State->get<AccumLenVarForBaseMap>(FromReg);
  if (!AccumVarP || !*AccumVarP)
    return false;

  return (*AccumVarP == LenVarReg);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!callNamed(Call, C, "copy_to_user"))
    return;

  ProgramStateRef State = C.getState();

  // copy_to_user(to, from, len)
  const MemRegion *FromReg = getArgBaseRegion(Call, 1, C);
  if (!FromReg)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(FromReg);
  if (!Kind)
    return;

  // Zeroed allocation (safe)
  if (*Kind == 1)
    return;

  // Only warn for possibly-uninitialized allocations
  if (*Kind != 2)
    return;

  // Recognize and suppress false positives when a known producer initialized exactly the copied bytes.
  if (isFalsePositiveDueToProducer(Call, C, FromReg))
    return;

  // Suppress when there is clear memcpy-accumulator pattern: memcpy(lenSym) followed by accum += lenSym and then copying accum.
  if (suppressDueToAccumulatorPattern(Call, C, FromReg))
    return;

  // Suppress when the most recent write into the source buffer used exactly the same length symbol from offset 0.
  if (suppressDueToLastWriteSymbol(Call, C, FromReg))
    return;

  // Evaluate the length if possible.
  uint64_t CopyLen = 0;
  bool LenKnown = false;
  const Expr *LenE = Call.getArgExpr(2);
  if (LenE) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, LenE, C)) {
      CopyLen = EvalRes.getZExtValue();
      LenKnown = true;
    }
  }

  const uint64_t *ZeroedBytes = State->get<ZeroInitSizeMap>(FromReg);
  const uint64_t *InitPrefix = State->get<InitPrefixMap>(FromReg);
  const unsigned *WriteCnt   = State->get<WriteCountMap>(FromReg);

  // If copy length is symbolic, try to infer a safe upper bound.
  if (!LenKnown) {
    SVal LenSV = Call.getArgSVal(2);
    if (SymbolRef Sym = LenSV.getAsSymbol()) {
      if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
        CopyLen = MaxV->getZExtValue();
        LenKnown = true;
      }
    }
  }

  if (LenKnown) {
    if ((ZeroedBytes && *ZeroedBytes >= CopyLen) ||
        (InitPrefix && *InitPrefix >= CopyLen)) {
      return; // Fully initialized (zeroed or written)
    }
    reportLeak(Call, C, FromReg);
    return;
  }

  // Fallback: If we can't reason about exact len, be conservative but avoid known structured-initialization false positives.
  // Heuristic: if we initialized strictly beyond the header size and observed multiple distinct writes, suppress.
  uint64_t HeaderSize = 0;
  if (const Expr *FromE = Call.getArgExpr(1)) {
    QualType PT = FromE->getType();
    if (!PT.isNull() && PT->isPointerType()) {
      QualType Pointee = PT->getPointeeType();
      HeaderSize = getTypeSizeInBytes(Pointee, C.getASTContext());
    }
  }

  if (InitPrefix && *InitPrefix > HeaderSize && WriteCnt && *WriteCnt >= 3) {
    return; // Appears to be a fully populated struct/array; avoid false positive.
  }

  // No evidence that the copied bytes are fully initialized.
  reportLeak(Call, C, FromReg);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;

  // Record direct store to subregions (fields/elements) to update initialized prefix.
  tryRecordDirectStore(LHS, C);

  // Detect "accum += lenSym" immediately after memcpy(..., lenSym)
  if (const auto *CAO = dyn_cast_or_null<CompoundAssignOperator>(StoreE)) {
    if (CAO->getOpcode() == BO_AddAssign) {
      // RHS symbol
      const Expr *RHS = CAO->getRHS();
      if (RHS) {
        SVal RHSSV = State->getSVal(RHS, C.getLocationContext());
        if (SymbolRef LenSym = RHSSV.getAsSymbol()) {
          // Do we know which base was last written with this length?
          if (const MemRegion *const *BaseP = State->get<LenSymToBaseMap>(LenSym)) {
            const MemRegion *Base = *BaseP;
            if (Base) {
              // Map base -> accumulator variable region
              const MemRegion *LBase = LHS->getBaseRegion();
              if (LBase) {
                const MemRegion *CanonBase = canonical(State, Base);
                const MemRegion *CanonLBase = canonical(State, LBase);
                if (CanonBase && CanonLBase) {
                  State = State->set<AccumLenVarForBaseMap>(CanonBase, CanonLBase);
                  C.addTransition(State);
                }
              }
            }
          }
        }
      }
    }
  }

  // Track pointer aliasing for future canonicalization.
  const MemRegion *LBase = LHS->getBaseRegion();
  const MemRegion *RHS = Val.getAsRegion();
  if (!LBase || !RHS)
    return;
  RHS = RHS->getBaseRegion();
  if (!RHS)
    return;

  const MemRegion *LC = canonical(State, LBase);
  const MemRegion *RC = canonical(State, RHS);
  if (!LC || !RC)
    return;

  State = State->set<PtrAliasMap>(LC, RC);
  State = State->set<PtrAliasMap>(RC, LC);
  C.addTransition(State);
}

void SAGenTestChecker::tryRecordDirectStore(const MemRegion *StoreR, CheckerContext &C) const {
  if (!StoreR)
    return;

  // Skip bit-field stores; they won't give us full-byte coverage.
  if (const auto *FR = dyn_cast<FieldRegion>(StoreR)) {
    if (FR->getDecl()->isBitField())
      return;
  }

  QualType VT;
  if (const auto *TVR = dyn_cast<TypedValueRegion>(StoreR)) {
    VT = TVR->getValueType();
  }
  if (VT.isNull())
    return;

  uint64_t SizeBytes = getTypeSizeInBytes(VT, C.getASTContext());
  if (SizeBytes == 0)
    return;

  markBytesWrittenToRegion(StoreR, SizeBytes, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect kmalloc buffers copied to userspace without full initialization (kernel info leak)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
