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

// Additional includes
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a Program State map to associate memory regions to their "fully initialized" state.
// true means the structure has been cleared (e.g. via memset), false means it remains partially uninitialized.
REGISTER_MAP_WITH_PROGRAMSTATE(InitializedMap, const MemRegion*, bool)
// (Optional) Map to track pointer aliasing.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

/// Helper: Check if the function call comes from a call to memset.
static bool isMemsetCall(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, "memset", C);
}

/// Helper: Check if the function call is one of the copy-to-user functions we care about,
/// here we target "nla_put" and "nla_put_64bit".
static bool isCopyToUserCall(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  // We check for both "nla_put" and "nla_put_64bit".
  return (ExprHasName(OriginExpr, "nla_put", C) ||
          ExprHasName(OriginExpr, "nla_put_64bit", C));
}

/// The checker class.
class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>, check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(static_cast<const CheckerBase*>(this),
                       "Kernel InfoLeak", "Kernel InfoLeak")) {}

  // Callback when a DeclStmt is finished (post-statement).
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;

  // Callback after a function call returns.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback before a function call is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

//
// Implementation of checkPostStmt: record local declarations for the target structure.
// We are looking for variables of type "struct tc_skbmod" that are declared on the stack.
//
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Iterate through each declared variable.
  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    // Check if the variable type's name contains "tc_skbmod".
    std::string TypeStr = VD->getType().getAsString();
    if (TypeStr.find("tc_skbmod") == std::string::npos)
      continue;

    // Retrieve the program state value for the variable.
    // Use State->getLValue instead of C.getSVal which expects a Stmt.
    SVal VarVal = State->getLValue(VD, C.getLocationContext());
    const MemRegion *MR = VarVal.getAsRegion();
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Initially mark the structure as uninitialized.
    State = State->set<InitializedMap>(MR, false);
    C.addTransition(State);
  }
}

//
// Implementation of checkPostCall: intercept memset calls to mark variables as fully initialized.
//
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If this call is to memset...
  if (isMemsetCall(Call, C)) {
    // In memset, the first argument is the destination.
    if (Call.getNumArgs() < 1)
      return;
    SVal DestVal = Call.getArgSVal(0);
    const MemRegion *MR = DestVal.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;
    // Mark this region as fully initialized.
    State = State->set<InitializedMap>(MR, true);
    C.addTransition(State);
  }
}

//
// Implementation of checkPreCall: intercept calls that copy data to user space.
// We look for calls to "nla_put" and "nla_put_64bit" and examine their arguments.
//
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (!isCopyToUserCall(Call, C))
    return;

  // For both "nla_put" and "nla_put_64bit", the relevant argument is typically the
  // pointer to the structure being copied. In our bug example, it is the fourth argument (index 3).
  if (Call.getNumArgs() < 4)
    return;

  SVal SrcVal = Call.getArgSVal(3);
  const MemRegion *MR = SrcVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Look up the initialization status.
  const bool *Initialized = State->get<InitializedMap>(MR);
  if (Initialized && !(*Initialized)) {
    // The structure has not been fully initialized (i.e. no memset was applied).
    // Report a potential kernel infoleak.
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Kernel infoleak: partially initialized structure copied to user space", N);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
  // No state transition is needed here.
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects partially initialized structures that may lead to kernel-infoleak",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
