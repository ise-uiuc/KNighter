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
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state sets for tracking device-provided lengths and validations.
REGISTER_SET_WITH_PROGRAMSTATE(DeviceLenRegions, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(DeviceLenSyms, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(ValidatedRegions, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(ValidatedSyms, SymbolRef)

namespace {

class SAGenTestChecker
  : public Checker<
        check::BeginFunction,
        check::PostCall,
        check::PreCall,
        check::Bind,
        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unvalidated device-provided length", "Memory Safety")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  bool isVirtioConfigRead(const CallEvent &Call, CheckerContext &C) const;
  bool isCopySizeCall(const CallEvent &Call, unsigned &LenIndex, CheckerContext &C) const;
  void markLenRegionAsDeviceProvided(const MemRegion *MR, CheckerContext &C) const;
  void markLenSymbolAsDeviceProvided(SymbolRef Sym, CheckerContext &C) const;
  void markValidatedRegion(const MemRegion *MR, CheckerContext &C) const;
  void markValidatedSymbol(SymbolRef Sym, CheckerContext &C) const;
  bool isRegionDeviceLen(const MemRegion *MR, ProgramStateRef State) const;
  bool isSymbolDeviceLen(SymbolRef Sym, ProgramStateRef State) const;
  bool isRegionValidated(const MemRegion *MR, ProgramStateRef State) const;
  bool isSymbolValidated(SymbolRef Sym, ProgramStateRef State) const;
  void tryRecordAssignmentLHSForCallResult(const CallEvent &Call, CheckerContext &C) const;
  void reportUnvalidatedLenUse(const CallEvent &Call, const Expr *LenE, CheckerContext &C) const;
};

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  // ProgramState maps/sets are empty by default for each function context.
  // Nothing to do here; kept for completeness per plan.
}

bool SAGenTestChecker::isVirtioConfigRead(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Only track these specific virtio config read helpers.
  if (ExprHasName(OriginExpr, "virtio_cread8", C) ||
      ExprHasName(OriginExpr, "virtio_cread16", C) ||
      ExprHasName(OriginExpr, "virtio_cread32", C))
    return true;

  return false;
}

bool SAGenTestChecker::isCopySizeCall(const CallEvent &Call, unsigned &LenIndex, CheckerContext &C) const {
  LenIndex = 0;
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // memcpy(void *dst, const void *src, size_t n)
  if (ExprHasName(OriginExpr, "memcpy", C)) {
    LenIndex = 2;
    return (Call.getNumArgs() > LenIndex);
  }

  // memmove(void *dst, const void *src, size_t n)
  if (ExprHasName(OriginExpr, "memmove", C)) {
    LenIndex = 2;
    return (Call.getNumArgs() > LenIndex);
  }

  // sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen)
  if (ExprHasName(OriginExpr, "sg_init_one", C)) {
    LenIndex = 2;
    return (Call.getNumArgs() > LenIndex);
  }

  return false;
}

void SAGenTestChecker::markLenRegionAsDeviceProvided(const MemRegion *MR, CheckerContext &C) const {
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;

  ProgramStateRef State = C.getState();
  if (!State->contains<DeviceLenRegions>(MR)) {
    State = State->add<DeviceLenRegions>(MR);
    // If it was previously validated spuriously, drop validation for conservativeness
    if (State->contains<ValidatedRegions>(MR))
      State = State->remove<ValidatedRegions>(MR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::markLenSymbolAsDeviceProvided(SymbolRef Sym, CheckerContext &C) const {
  if (!Sym) return;
  ProgramStateRef State = C.getState();
  if (!State->contains<DeviceLenSyms>(Sym)) {
    State = State->add<DeviceLenSyms>(Sym);
    if (State->contains<ValidatedSyms>(Sym))
      State = State->remove<ValidatedSyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::markValidatedRegion(const MemRegion *MR, CheckerContext &C) const {
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;
  ProgramStateRef State = C.getState();
  if (!State->contains<ValidatedRegions>(MR)) {
    State = State->add<ValidatedRegions>(MR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::markValidatedSymbol(SymbolRef Sym, CheckerContext &C) const {
  if (!Sym) return;
  ProgramStateRef State = C.getState();
  if (!State->contains<ValidatedSyms>(Sym)) {
    State = State->add<ValidatedSyms>(Sym);
    C.addTransition(State);
  }
}

bool SAGenTestChecker::isRegionDeviceLen(const MemRegion *MR, ProgramStateRef State) const {
  if (!MR) return false;
  MR = MR->getBaseRegion();
  if (!MR) return false;
  return State->contains<DeviceLenRegions>(MR);
}

bool SAGenTestChecker::isSymbolDeviceLen(SymbolRef Sym, ProgramStateRef State) const {
  if (!Sym) return false;
  return State->contains<DeviceLenSyms>(Sym);
}

bool SAGenTestChecker::isRegionValidated(const MemRegion *MR, ProgramStateRef State) const {
  if (!MR) return false;
  MR = MR->getBaseRegion();
  if (!MR) return false;
  return State->contains<ValidatedRegions>(MR);
}

bool SAGenTestChecker::isSymbolValidated(SymbolRef Sym, ProgramStateRef State) const {
  if (!Sym) return false;
  return State->contains<ValidatedSyms>(Sym);
}

// When a virtio_cread* call is used in an assignment or initialization,
// try to identify and record the LHS region as a device-provided length.
void SAGenTestChecker::tryRecordAssignmentLHSForCallResult(const CallEvent &Call, CheckerContext &C) const {
  const Expr *CallE = dyn_cast_or_null<Expr>(Call.getOriginExpr());
  if (!CallE)
    return;

  // Case 1: Parent assignment 'LHS = virtio_cread*()'
  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(CallE, C)) {
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS();
      if (LHS) {
        const MemRegion *MR = getMemRegionFromExpr(LHS, C);
        if (MR) {
          MR = MR->getBaseRegion();
          markLenRegionAsDeviceProvided(MR, C);
        }
      }
    }
  }

  // Case 2: Declaration with init 'u8 len = virtio_cread*()'
  if (const auto *DS = findSpecificTypeInParents<DeclStmt>(CallE, C)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (const Expr *Init = VD->getInit()) {
          // Ensure this var is initialized from this exact call.
          const CallExpr *InnerCall = findSpecificTypeInChildren<CallExpr>(Init);
          if (!InnerCall || InnerCall != CallE)
            continue;
          const MemRegion *MR = getMemRegionFromExpr(Init, C);
          if (!MR) {
            // If Init region retrieval fails, try region of the Var itself.
            SVal LVal = C.getSValBuilder().getLValue(VD, C.getLocationContext());
            MR = LVal.getAsRegion();
          }
          if (MR) {
            MR = MR->getBaseRegion();
            markLenRegionAsDeviceProvided(MR, C);
          }
        }
      }
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isVirtioConfigRead(Call, C))
    return;

  // Mark the return symbol (if any) as device-provided length.
  SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
  if (RetSym)
    markLenSymbolAsDeviceProvided(RetSym, C);

  // Try to find the LHS region into which the result is stored and mark it.
  tryRecordAssignmentLHSForCallResult(Call, C);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *DestR = Loc.getAsRegion();
  if (!DestR)
    return;
  DestR = DestR->getBaseRegion();
  if (!DestR)
    return;

  const MemRegion *SrcR = Val.getAsRegion();
  if (SrcR)
    SrcR = SrcR->getBaseRegion();

  SymbolRef SrcSym = Val.getAsSymbol();

  bool PropagateDevice = false;
  bool PropagateValidated = false;

  if (SrcR && isRegionDeviceLen(SrcR, State))
    PropagateDevice = true;
  if (SrcSym && isSymbolDeviceLen(SrcSym, State))
    PropagateDevice = true;

  if (SrcR && isRegionValidated(SrcR, State))
    PropagateValidated = true;
  if (SrcSym && isSymbolValidated(SrcSym, State))
    PropagateValidated = true;

  if (PropagateDevice) {
    State = State->add<DeviceLenRegions>(DestR);
    // Do not automatically clear validation state here; use separate logic.
  }
  if (PropagateValidated) {
    State = State->add<ValidatedRegions>(DestR);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Look for any comparison involving the macro VIRTIO_NET_RSS_MAX_KEY_SIZE
  // and a device-provided length region/symbol.
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE->IgnoreParenCasts());
  if (!BO)
    BO = findSpecificTypeInChildren<BinaryOperator>(Condition);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  switch (Op) {
    case BO_GT: case BO_GE:
    case BO_LT: case BO_LE:
    case BO_EQ: case BO_NE:
      break;
    default:
      return;
  }

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  ProgramStateRef State = C.getState();

  // Helper lambda to attempt marking validated if one side is device-len and the other mentions the macro.
  auto TryValidate = [&](const Expr *LenSide, const Expr *MacroSide) {
    bool MacroMentioned = ExprHasName(MacroSide, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C);
    if (!MacroMentioned)
      return false;

    const MemRegion *MR = getMemRegionFromExpr(LenSide, C);
    if (MR)
      MR = MR->getBaseRegion();
    SymbolRef Sym = State->getSVal(LenSide, C.getLocationContext()).getAsSymbol();

    bool IsDev = (MR && isRegionDeviceLen(MR, State)) || (Sym && isSymbolDeviceLen(Sym, State));
    if (!IsDev)
      return false;

    if (MR)
      markValidatedRegion(MR, C);
    if (Sym)
      markValidatedSymbol(Sym, C);
    return true;
  };

  bool Changed = false;
  Changed |= TryValidate(LHS, RHS);
  Changed |= TryValidate(RHS, LHS);

  if (Changed)
    return; // Transitions already added by markValidated*
}

void SAGenTestChecker::reportUnvalidatedLenUse(const CallEvent &Call, const Expr *LenE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unvalidated device-provided length used as copy size (possible OOB).", N);
  if (LenE)
    R->addRange(LenE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned LenIndex = 0;
  if (!isCopySizeCall(Call, LenIndex, C))
    return;

  if (Call.getNumArgs() <= LenIndex)
    return;

  const Expr *LenE = Call.getArgExpr(LenIndex);
  if (!LenE)
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *LenR = getMemRegionFromExpr(LenE, C);
  if (LenR)
    LenR = LenR->getBaseRegion();
  SymbolRef LenSym = State->getSVal(LenE, C.getLocationContext()).getAsSymbol();

  bool IsDevLen = (LenR && isRegionDeviceLen(LenR, State)) ||
                  (LenSym && isSymbolDeviceLen(LenSym, State));

  if (!IsDevLen)
    return;

  bool IsValidated = (LenR && isRegionValidated(LenR, State)) ||
                     (LenSym && isSymbolValidated(LenSym, State));

  if (!IsValidated) {
    reportUnvalidatedLenUse(Call, LenE, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects using device-provided length without validating against VIRTIO_NET_RSS_MAX_KEY_SIZE in size-sensitive calls",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
