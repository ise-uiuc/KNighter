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
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/APInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track possibly-uninitialized heap buffers (kmalloc).
REGISTER_MAP_WITH_PROGRAMSTATE(UninitBufMap, const MemRegion*, bool)
// Program state: record allocation byte size when known.
REGISTER_MAP_WITH_PROGRAMSTATE(AllocByteSizeMap, const MemRegion*, uint64_t)
// Program state: track simple pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::Bind,
    check::RegionChanges
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel info leak (copy_to_user)", "Security")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
      ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                         const InvalidatedSymbols *Invalidated,
                                         ArrayRef<const MemRegion *> ExplicitRegions,
                                         ArrayRef<const MemRegion *> Regions,
                                         const LocationContext *LCtx,
                                         const CallEvent *Call) const;

   private:
      // Helpers
      static const MemRegion* getBase(const MemRegion *R) {
        return R ? R->getBaseRegion() : nullptr;
      }

      static const MemRegion* resolveAlias(const MemRegion *R, ProgramStateRef S) {
        const MemRegion *Cur = getBase(R);
        // Chase a few hops to find the canonical region.
        for (int i = 0; i < 6 && Cur; ++i) {
          if (const MemRegion *Next = S->get<PtrAliasMap>(Cur)) {
            Cur = getBase(Next);
            continue;
          }
          break;
        }
        return Cur;
      }

      static bool getArgConstUInt(const CallEvent &Call, unsigned Idx,
                                  CheckerContext &C, uint64_t &Out) {
        if (Idx >= Call.getNumArgs())
          return false;
        const Expr *E = Call.getArgExpr(Idx);
        if (!E)
          return false;
        llvm::APSInt V;
        if (!EvaluateExprToInt(V, E, C))
          return false;
        if (V.isSigned() && V.isNegative())
          return false;
        Out = V.getZExtValue();
        return true;
      }

      static bool callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name) {
        const Expr *Origin = Call.getOriginExpr();
        if (!Origin)
          return false;
        return ExprHasName(Origin, Name, C);
      }

      void markAllocUninitAndSize(const CallEvent &Call, CheckerContext &C,
                                  unsigned SizeArgIndex) const {
        ProgramStateRef State = C.getState();
        const MemRegion *MR = Call.getReturnValue().getAsRegion();
        if (!MR)
          return;
        MR = MR->getBaseRegion();
        if (!MR)
          return;

        // Mark as possibly-uninitialized.
        State = State->set<UninitBufMap>(MR, true);

        // Try to record the allocation size if it's a constant.
        uint64_t SizeBytes = 0;
        if (getArgConstUInt(Call, SizeArgIndex, C, SizeBytes)) {
          State = State->set<AllocByteSizeMap>(MR, SizeBytes);
        } else {
          State = State->remove<AllocByteSizeMap>(MR);
        }

        C.addTransition(State);
      }

      void markAllocZeroedAndSize(const CallEvent &Call, CheckerContext &C,
                                  unsigned SizeArgIndex) const {
        ProgramStateRef State = C.getState();
        const MemRegion *MR = Call.getReturnValue().getAsRegion();
        if (!MR)
          return;
        MR = MR->getBaseRegion();
        if (!MR)
          return;

        // Fully zero-initialized.
        State = State->remove<UninitBufMap>(MR);

        // Try to record size.
        uint64_t SizeBytes = 0;
        if (getArgConstUInt(Call, SizeArgIndex, C, SizeBytes)) {
          State = State->set<AllocByteSizeMap>(MR, SizeBytes);
        } else {
          State = State->remove<AllocByteSizeMap>(MR);
        }

        C.addTransition(State);
      }

      void markKcallocZeroedAndSize(const CallEvent &Call, CheckerContext &C,
                                    unsigned NmembIdx, unsigned SizeIdx) const {
        ProgramStateRef State = C.getState();
        const MemRegion *MR = Call.getReturnValue().getAsRegion();
        if (!MR)
          return;
        MR = MR->getBaseRegion();
        if (!MR)
          return;

        State = State->remove<UninitBufMap>(MR);

        uint64_t Nmemb = 0, Sz = 0;
        if (getArgConstUInt(Call, NmembIdx, C, Nmemb) &&
            getArgConstUInt(Call, SizeIdx, C, Sz)) {
          __uint128_t Prod = static_cast<__uint128_t>(Nmemb) * static_cast<__uint128_t>(Sz);
          if (Prod <= std::numeric_limits<uint64_t>::max()) {
            State = State->set<AllocByteSizeMap>(MR, static_cast<uint64_t>(Prod));
          } else {
            State = State->remove<AllocByteSizeMap>(MR);
          }
        } else {
          State = State->remove<AllocByteSizeMap>(MR);
        }

        C.addTransition(State);
      }

      void maybeHandleMemset(const CallEvent &Call, CheckerContext &C) const {
        // We only care about memset(ptr, 0, len) that fully covers the allocation.
        if (!callHasName(Call, C, "memset"))
          return;
        if (Call.getNumArgs() < 3)
          return;

        ProgramStateRef State = C.getState();

        // Check value == 0
        uint64_t Val = 0;
        if (!getArgConstUInt(Call, 1, C, Val) || Val != 0)
          return;

        // Length
        uint64_t Len = 0;
        if (!getArgConstUInt(Call, 2, C, Len))
          return;

        const Expr *DstE = Call.getArgExpr(0);
        if (!DstE)
          return;

        const MemRegion *DstR = getMemRegionFromExpr(DstE, C);
        if (!DstR)
          return;
        DstR = resolveAlias(getBase(DstR), State);
        if (!DstR)
          return;

        const bool *Uninit = State->get<UninitBufMap>(DstR);
        if (!Uninit || !*Uninit)
          return;

        const uint64_t *AllocSize = State->get<AllocByteSizeMap>(DstR);
        if (!AllocSize)
          return;

        if (Len >= *AllocSize) {
          State = State->remove<UninitBufMap>(DstR);
          C.addTransition(State);
        }
      }

      void reportLeak(const CallEvent &Call, CheckerContext &C, const Expr *SrcArg) const {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          return;
        auto R = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "copy_to_user from kmalloc() buffer may leak uninitialized bytes; use kzalloc() or clear the buffer",
            N);
        if (SrcArg)
          R->addRange(SrcArg->getSourceRange());
        else
          R->addRange(Call.getSourceRange());
        C.emitReport(std::move(R));
      }
};

// Track allocations and zeroing calls.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // kmalloc(size, gfp)
  if (callHasName(Call, C, "kmalloc")) {
    markAllocUninitAndSize(Call, C, 0);
    return;
  }

  // kzalloc(size, gfp), kvzalloc(size, gfp)
  if (callHasName(Call, C, "kzalloc") || callHasName(Call, C, "kvzalloc")) {
    markAllocZeroedAndSize(Call, C, 0);
    return;
  }

  // kcalloc(nmemb, size, gfp)
  if (callHasName(Call, C, "kcalloc")) {
    markKcallocZeroedAndSize(Call, C, 0, 1);
    return;
  }

  // memset(ptr, 0, len)
  maybeHandleMemset(Call, C);
}

// Detect copy_to_user and frees.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // copy_to_user(user_dst, kernel_src, size)
  if (callHasName(Call, C, "copy_to_user")) {
    if (Call.getNumArgs() < 2)
      return;
    const Expr *SrcE = Call.getArgExpr(1);
    const MemRegion *SrcR = nullptr;
    if (SrcE)
      SrcR = getMemRegionFromExpr(SrcE, C);
    if (!SrcR) {
      // Fall back to SVal if needed.
      SVal Arg1 = Call.getArgSVal(1);
      SrcR = Arg1.getAsRegion();
    }
    if (!SrcR)
      return;

    SrcR = resolveAlias(getBase(SrcR), State);
    if (!SrcR)
      return;

    const bool *Uninit = State->get<UninitBufMap>(SrcR);
    if (!Uninit || !*Uninit)
      return;

    // Optional refinement: if copy length is known smaller than alloc size, skip.
    const uint64_t *AllocSize = State->get<AllocByteSizeMap>(SrcR);
    uint64_t CopyLen = 0;
    bool HasCopyLen = getArgConstUInt(Call, 2, C, CopyLen);

    if (AllocSize && HasCopyLen && CopyLen < *AllocSize) {
      return; // likely copying only initialized prefix
    }

    reportLeak(Call, C, SrcE);
    return;
  }

  // Free: kfree(ptr), kvfree(ptr)
  if (callHasName(Call, C, "kfree") || callHasName(Call, C, "kvfree")) {
    if (Call.getNumArgs() < 1)
      return;
    const Expr *PtrE = Call.getArgExpr(0);
    const MemRegion *R = nullptr;
    if (PtrE)
      R = getMemRegionFromExpr(PtrE, C);
    if (!R) {
      R = Call.getArgSVal(0).getAsRegion();
    }
    if (!R)
      return;
    R = resolveAlias(getBase(R), State);
    if (!R)
      return;

    State = State->remove<UninitBufMap>(R);
    State = State->remove<AllocByteSizeMap>(R);
    State = State->remove<PtrAliasMap>(R);
    C.addTransition(State);
    return;
  }
}

// Record pointer aliasing: p2 = p1
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS) {
    C.addTransition(State);
    return;
  }
  LHS = LHS->getBaseRegion();
  if (!LHS) {
    C.addTransition(State);
    return;
  }

  if (const MemRegion *RHS = Val.getAsRegion()) {
    RHS = RHS->getBaseRegion();
    if (RHS) {
      State = State->set<PtrAliasMap>(LHS, RHS);
      State = State->set<PtrAliasMap>(RHS, LHS);
      C.addTransition(State);
      return;
    }
  }

  // If assigning NULL, drop alias info for LHS.
  if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
    if (CI->getValue().isZero()) {
      State = State->remove<PtrAliasMap>(LHS);
      C.addTransition(State);
      return;
    }
  }

  C.addTransition(State);
}

// Cleanup on region invalidation.
ProgramStateRef SAGenTestChecker::checkRegionChanges(ProgramStateRef State,
                                                     const InvalidatedSymbols *Invalidated,
                                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                                     ArrayRef<const MemRegion *> Regions,
                                                     const LocationContext *LCtx,
                                                     const CallEvent *Call) const {
  auto Cleanup = [&State](ArrayRef<const MemRegion *> Regs) {
    for (const MemRegion *R : Regs) {
      if (!R) continue;
      const MemRegion *B = R->getBaseRegion();
      if (!B) continue;
      State = State->remove<UninitBufMap>(B);
      State = State->remove<AllocByteSizeMap>(B);
      State = State->remove<PtrAliasMap>(B);
    }
  };
  Cleanup(ExplicitRegions);
  Cleanup(Regions);
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects copy_to_user from kmalloc() buffers that may contain uninitialized bytes",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
