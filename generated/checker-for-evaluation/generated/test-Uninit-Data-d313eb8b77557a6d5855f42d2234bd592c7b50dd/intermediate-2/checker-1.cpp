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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states:
// Map to track whether a region (typically stack-allocated struct) is fully zeroed.
REGISTER_MAP_WITH_PROGRAMSTATE(StructZeroedMap, const MemRegion*, bool)
// Map to track pointer aliasing between memory regions.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Kernel info-leak: Uninitialized Padding")) {}

  // Callback: Invoked before a call occurs.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback: Invoked immediately after a call returns.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback: Invoked when a value is bound to a memory region.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper function to report bug.
  void reportUninitializedStruct(const MemRegion *MR, const CallEvent &Call,
                                 CheckerContext &C) const;
  // Helper function to propagate the "zeroed" flag via pointer aliasing.
  ProgramStateRef propagateZeroedFlag(ProgramStateRef State,
                                        const MemRegion *DestMR,
                                        const MemRegion *SrcMR) const;
};

///////////////////////////////////////////////////////////////////////////
// checkPostCall: Track memset calls to mark regions as fully zeroed.
///////////////////////////////////////////////////////////////////////////
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Use utility method ExprHasName to match the callee "memset"
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "memset", C))
    return;

  // For memset, the first argument is the destination pointer.
  if (Call.getNumArgs() < 1)
    return;
  SVal DestVal = Call.getArgSVal(0);
  const MemRegion *MR = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark the region as fully zeroed.
  State = State->set<StructZeroedMap>(MR, true);
  C.addTransition(State);
}

///////////////////////////////////////////////////////////////////////////
// checkPreCall: Intercepts calls to copy_to_user to check if the source
// structure is fully initialized (i.e. zeroed) to avoid copying uninitialized padding.
///////////////////////////////////////////////////////////////////////////
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check for calls to "copy_to_user". Use ExprHasName for accuracy.
  if (!ExprHasName(OriginExpr, "copy_to_user", C))
    return;
  
  // According to convention, copy_to_user(user_dest, kernel_src, size)
  // so the second argument is the kernel source.
  if (Call.getNumArgs() < 2)
    return;
  SVal KernelSrcVal = Call.getArgSVal(1);
  const MemRegion *MR = KernelSrcVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Check if this memory region, or any of its alias, has been marked as zeroed.
  const bool *Zeroed = State->get<StructZeroedMap>(MR);
  if (Zeroed && *Zeroed)
    return; // Properly initialized.

  // If we have pointer alias info, try to check the aliased region.
  if (const MemRegion * const *AliasMRP = State->get<PtrAliasMap>(MR)) {
    const MemRegion *AliasMR = *AliasMRP;
    if (AliasMR)
      AliasMR = AliasMR->getBaseRegion();
    if (AliasMR) {
      const bool *AliasZeroed = State->get<StructZeroedMap>(AliasMR);
      if (AliasZeroed && *AliasZeroed)
        return;
    }
  }

  // If not marked as fully zeroed, report potential bug.
  reportUninitializedStruct(MR, Call, C);
}

///////////////////////////////////////////////////////////////////////////
// checkBind: Propagate aliasing and zeroed flag information when pointers
// are assigned from one to another.
///////////////////////////////////////////////////////////////////////////
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;

  // Record alias information.
  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);

  // Propagate the zeroed flag if the source (RHS) is already marked zeroed.
  State = propagateZeroedFlag(State, LHSReg, RHSReg);
  C.addTransition(State);
}

///////////////////////////////////////////////////////////////////////////
// reportUninitializedStruct: Report the bug if an unzeroed (partially
// initialized) structure is passed to a copy_to_user call.
///////////////////////////////////////////////////////////////////////////
void SAGenTestChecker::reportUninitializedStruct(const MemRegion *MR,
                                                 const CallEvent &Call,
                                                 CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;

  auto Report =
      std::make_unique<PathSensitiveBugReport>(*BT,
          "Kernel info-leak: Structure with implicit padding is not fully zeroed",
          ErrNode);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

///////////////////////////////////////////////////////////////////////////
// propagateZeroedFlag: If the source pointer is marked as zeroed, update the
// destination pointer alias as zeroed.
///////////////////////////////////////////////////////////////////////////
ProgramStateRef SAGenTestChecker::propagateZeroedFlag(ProgramStateRef State,
                                                      const MemRegion *DestMR,
                                                      const MemRegion *SrcMR) const {
  const bool *SrcZeroed = State->get<StructZeroedMap>(SrcMR);
  if (SrcZeroed && *SrcZeroed) {
    State = State->set<StructZeroedMap>(DestMR, true);
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential kernel info-leak when partially initialized stack structures (with implicit padding) are copied to user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
