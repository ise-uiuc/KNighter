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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track device-provided length regions and whether they are validated.
REGISTER_MAP_WITH_PROGRAMSTATE(DeviceLenMap, const MemRegion*, bool)

namespace {
class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::BranchCondition,
        check::Bind> {

   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unvalidated device length", "Memory Safety")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      static bool isVirtioCreadScalar(const CallEvent &Call, CheckerContext &C);
      static bool isRelevantOffsetExpr(const Expr *E, CheckerContext &C);
      static const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C);

      static bool isMemCopyLike(const CallEvent &Call, unsigned &SizeIdx, unsigned &BufIdx, CheckerContext &C);
      static bool tryGetArraySizeForBufferArg(const Expr *BufExpr, CheckerContext &C, llvm::APInt &ArraySize);

      static bool exprHasRSSMaxMacro(const Expr *E, CheckerContext &C);

      void markLenValidatedOnBranch(const BinaryOperator *BO, CheckerContext &C) const;
      void reportUnvalidatedUse(const CallEvent &Call, CheckerContext &C) const;
};

static const MemRegion* getTrackedRegionFromState(ProgramStateRef State, const MemRegion *MR) {
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  if (!MR) return nullptr;
  const bool *Val = State->get<DeviceLenMap>(MR);
  return Val ? MR : nullptr;
}

bool SAGenTestChecker::isVirtioCreadScalar(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;

  // Use ExprHasName for robustness
  if (ExprHasName(Origin, "virtio_cread8", C)) return true;
  if (ExprHasName(Origin, "virtio_cread16", C)) return true;
  if (ExprHasName(Origin, "virtio_cread32", C)) return true;
  return false;
}

bool SAGenTestChecker::isRelevantOffsetExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  // We only care about reading rss_max_key_size or hash_key_length offsets
  if (ExprHasName(E, "rss_max_key_size", C)) return true;
  if (ExprHasName(E, "hash_key_length", C)) return true;
  return false;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

bool SAGenTestChecker::isMemCopyLike(const CallEvent &Call, unsigned &SizeIdx, unsigned &BufIdx, CheckerContext &C) {
  SizeIdx = BufIdx = (unsigned)-1;
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;

  // memcpy(dst, src, len)
  if (ExprHasName(Origin, "memcpy", C)) {
    if (Call.getNumArgs() >= 3) {
      BufIdx = 0; SizeIdx = 2; return true;
    }
  }
  // memmove(dst, src, len)
  if (ExprHasName(Origin, "memmove", C)) {
    if (Call.getNumArgs() >= 3) {
      BufIdx = 0; SizeIdx = 2; return true;
    }
  }
  // virtio_cread_bytes(dev, off, buf, len)
  if (ExprHasName(Origin, "virtio_cread_bytes", C)) {
    if (Call.getNumArgs() >= 4) {
      BufIdx = 2; SizeIdx = 3; return true;
    }
  }
  // virtio_cwrite_bytes(dev, off, buf, len)
  if (ExprHasName(Origin, "virtio_cwrite_bytes", C)) {
    if (Call.getNumArgs() >= 4) {
      BufIdx = 2; SizeIdx = 3; return true;
    }
  }
  // sg_init_one(sg, buf, len)
  if (ExprHasName(Origin, "sg_init_one", C)) {
    if (Call.getNumArgs() >= 3) {
      BufIdx = 1; SizeIdx = 2; return true;
    }
  }
  return false;
}

bool SAGenTestChecker::tryGetArraySizeForBufferArg(const Expr *BufExpr, CheckerContext &C, llvm::APInt &ArraySize) {
  if (!BufExpr) return false;

  // Try directly
  if (getArraySizeFromExpr(ArraySize, BufExpr))
    return true;

  // Try to find a DeclRefExpr child
  if (const auto *DRE = findSpecificTypeInChildren<DeclRefExpr>(BufExpr)) {
    if (getArraySizeFromExpr(ArraySize, DRE))
      return true;
  }
  return false;
}

bool SAGenTestChecker::exprHasRSSMaxMacro(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C);
}

// Step A: Mark device-provided size as unvalidated after virtio_cread8/16/32 for rss_max_key_size/hash_key_length
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isVirtioCreadScalar(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *OffsetExpr = Call.getArgExpr(1);
  if (!isRelevantOffsetExpr(OffsetExpr, C))
    return;

  // Find assignment of the call result: LHS = virtio_creadX(...)
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return;

  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(Origin, C);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  if (!LHS) return;

  const MemRegion *LHSMR = getBaseRegionFromExpr(LHS, C);
  if (!LHSMR) return;

  ProgramStateRef State = C.getState();
  State = State->set<DeviceLenMap>(LHSMR, /*Validated=*/false);
  C.addTransition(State);
}

// Step B: Recognize validation branches and mark as validated on safe branch
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) return;

  // Strip parens/casts
  CondE = CondE->IgnoreParenCasts();

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO) {
    // Try find a binary operator in children if directly not available
    BO = findSpecificTypeInChildren<BinaryOperator>(Condition);
  }
  if (!BO) return;

  // Only consider comparison operators
  BinaryOperator::Opcode Op = BO->getOpcode();
  switch (Op) {
  case BO_LT: case BO_LE: case BO_GT: case BO_GE:
    break;
  default:
    return;
  }

  ProgramStateRef State = C.getState();

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS) return;

  const MemRegion *LHSReg = getBaseRegionFromExpr(LHS, C);
  const MemRegion *RHSReg = getBaseRegionFromExpr(RHS, C);

  const bool *LHSTrackedVal = LHSReg ? State->get<DeviceLenMap>(LHSReg) : nullptr;
  const bool *RHSTrackedVal = RHSReg ? State->get<DeviceLenMap>(RHSReg) : nullptr;

  bool RHSHasMax = exprHasRSSMaxMacro(RHS, C);
  bool LHSHasMax = exprHasRSSMaxMacro(LHS, C);

  const MemRegion *SizeReg = nullptr;
  bool SafeOnTrue = false;
  bool Matched = false;

  // Case 1: size (tracked) on LHS, macro on RHS
  if (LHSTrackedVal && RHSHasMax) {
    SizeReg = LHSReg;
    Matched = true;
    // size < = MAX  -> True branch safe
    // size < MAX     -> True branch safe
    // size > = MAX   -> False branch safe
    // size > MAX     -> False branch safe
    if (Op == BO_LT || Op == BO_LE)
      SafeOnTrue = true;
    else if (Op == BO_GT || Op == BO_GE)
      SafeOnTrue = false;
  }

  // Case 2: macro on LHS, size (tracked) on RHS
  if (!Matched && RHSTrackedVal && LHSHasMax) {
    SizeReg = RHSReg;
    Matched = true;
    // MAX > size  -> True branch safe
    // MAX >= size -> True branch safe
    // MAX < size  -> False branch safe
    // MAX <= size -> False branch safe
    if (Op == BO_GT || Op == BO_GE)
      SafeOnTrue = true;
    else if (Op == BO_LT || Op == BO_LE)
      SafeOnTrue = false;
  }

  if (!Matched || !SizeReg)
    return;

  // Create two states for the branch; mark validated on safe branch.
  ProgramStateRef StateT = State;
  ProgramStateRef StateF = State;

  if (SafeOnTrue) {
    StateT = StateT->set<DeviceLenMap>(SizeReg, true);
  } else {
    StateF = StateF->set<DeviceLenMap>(SizeReg, true);
  }

  C.addTransition(StateT);
  C.addTransition(StateF);
}

// Step C: Detect unsafe uses of unvalidated device length as a size for memory operations
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SizeIdx = 0, BufIdx = 0;
  if (!isMemCopyLike(Call, SizeIdx, BufIdx, C))
    return;

  if (Call.getNumArgs() <= std::max(SizeIdx, BufIdx))
    return;

  const Expr *SizeExpr = Call.getArgExpr(SizeIdx);
  const MemRegion *SizeReg = getBaseRegionFromExpr(SizeExpr, C);
  ProgramStateRef State = C.getState();

  // If no region, try name-based heuristic: only proceed when name matches expected size fields.
  if (!SizeReg) {
    if (!(ExprHasName(SizeExpr, "rss_key_size", C) || ExprHasName(SizeExpr, "hash_key_length", C)))
      return;
    // We still need a region to consult the map. Try again.
    SizeReg = getBaseRegionFromExpr(SizeExpr, C);
  }
  if (!SizeReg)
    return;

  const bool *Validated = State->get<DeviceLenMap>(SizeReg);
  if (!Validated || *Validated == true)
    return; // Not tracked or already validated

  // Destination buffer should be a fixed-size array
  const Expr *BufExpr = Call.getArgExpr(BufIdx);
  llvm::APInt ArraySize;
  if (!tryGetArraySizeForBufferArg(BufExpr, C, ArraySize))
    return;

  // We have an unvalidated device length being used to copy into a fixed-size buffer -> warn
  reportUnvalidatedUse(Call, C);
}

// Step D: Propagate device length taint on simple assignments
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S) return;

  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(S, C);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS) return;

  const MemRegion *SrcReg = getBaseRegionFromExpr(RHS, C);
  const MemRegion *DstReg = getBaseRegionFromExpr(LHS, C);
  if (!SrcReg || !DstReg) return;

  ProgramStateRef State = C.getState();
  const bool *SrcTracked = State->get<DeviceLenMap>(SrcReg);
  if (!SrcTracked) return;

  State = State->set<DeviceLenMap>(DstReg, *SrcTracked);
  C.addTransition(State);
}

void SAGenTestChecker::reportUnvalidatedUse(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unvalidated device length used as copy size; check against VIRTIO_NET_RSS_MAX_KEY_SIZE.", N);
  if (const Stmt *S = Call.getOriginExpr())
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of unvalidated device-provided lengths for memory operations (virtio rss key size)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
