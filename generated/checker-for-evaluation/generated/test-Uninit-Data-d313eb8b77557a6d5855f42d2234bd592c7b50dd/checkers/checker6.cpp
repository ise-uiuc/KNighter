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

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map for tracking whether a structure (pointed-to by a MemRegion)
// has been fully cleared (i.e., initialized) via memset.
REGISTER_MAP_WITH_PROGRAMSTATE(InitStructMap, const MemRegion*, bool)
// Optional: Register a program state map for aliasing between pointer regions.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

//---------------------------------------------------------------------
// Checker Implementation
//---------------------------------------------------------------------
namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Uninitialized Structure Padding",
                                         "Kernel Infoleak")) {}

  // Callback: Intercept calls after they have been evaluated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: Intercept calls before they are evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: Track pointer aliasing.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Report an error if a structure that may have uninitialized padding is copied to user space.
  void reportUninitPadding(const MemRegion *MR, CheckerContext &C, const SourceRange &R) const;
};

// checkPostCall: Look for calls to memset, and if the call clears a structure (i.e. setting to 0),
// mark that structure's memory region in our InitStructMap as initialized.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Use the origin expression to check function name.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;
  // Check if the call is to memset.
  if (!ExprHasName(Origin, "memset", C))
    return;

  // Ensure that the second argument (the value to set) is a constant zero.
  const Expr *ValExpr = Call.getArgExpr(1);
  if (!ValExpr)
    return;
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, ValExpr, C))
    return;
  if (EvalRes != 0)
    return;

  // Get the destination pointer (the first argument) of memset.
  const Expr *DestExpr = Call.getArgExpr(0);
  if (!DestExpr)
    return;
  const MemRegion *MR = getMemRegionFromExpr(DestExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark the region as fully initialized.
  ProgramStateRef State = C.getState();
  State = State->set<InitStructMap>(MR, true);

  // Also, update alias information if available.
  if (const MemRegion *const *Alias = State->get<PtrAliasMap>(MR)) {
    State = State->set<InitStructMap>(*Alias, true);
  }
  C.addTransition(State);
}

// checkPreCall: Look for calls copying kernel data to user space, e.g.
// copy_to_user, nla_put, or nla_put_64bit. For these calls, check if the source
// buffer being copied has been fully initialized.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = nullptr;
  SourceRange SR = Call.getSourceRange();

  // Determine which function is being called and pick the appropriate argument
  // containing the source buffer.
  if (ExprHasName(Origin, "copy_to_user", C)) {
    // In copy_to_user(dest, src, size), the source pointer is the second argument.
    if (Call.getNumArgs() < 2)
      return;
    MR = getMemRegionFromExpr(Call.getArgExpr(1), C);
  } else if (ExprHasName(Origin, "nla_put", C)) {
    // In nla_put(skb, attrtype, len, data), the data pointer (source buffer) is the fourth argument.
    if (Call.getNumArgs() < 4)
      return;
    MR = getMemRegionFromExpr(Call.getArgExpr(3), C);
  } else if (ExprHasName(Origin, "nla_put_64bit", C)) {
    // Similar: assume data pointer is the fourth argument.
    if (Call.getNumArgs() < 4)
      return;
    MR = getMemRegionFromExpr(Call.getArgExpr(3), C);
  } else {
    return;
  }

  if (!MR)
    return;
  MR = MR->getBaseRegion();

  // Look up the initialization flag in our state.
  const bool *IsInit = State->get<InitStructMap>(MR);
  // If no mapping exists, or if the flag is false then the structure may have
  // uninitialized padding.
  if (!IsInit || !(*IsInit)) {
    reportUninitPadding(MR, C, SR);
  }
}

// checkBind: Record pointer aliasing. When a pointer is bound from one to another
// (e.g. p2 = p1) then record this relationship in PtrAliasMap, so that if one of them
// is marked as cleared via memset, its aliased pointer will inherit the initialization property.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  if (!LHS)
    return;
  if (const MemRegion *RHS = Val.getAsRegion()) {
    RHS = RHS->getBaseRegion();
    if (!RHS)
      return;
    // Record aliasing both ways.
    State = State->set<PtrAliasMap>(LHS, RHS);
    State = State->set<PtrAliasMap>(RHS, LHS);
  }
  C.addTransition(State);
}

// reportUninitPadding: Generate a bug report for when uninitialized padding is
// copied to user space.
void SAGenTestChecker::reportUninitPadding(const MemRegion *MR, CheckerContext &C,
                                             const SourceRange &SR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Uninitialized padding in structure when copying to user space", N);
  Report->addRange(SR);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects uninitialized structure padding before copying to user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
