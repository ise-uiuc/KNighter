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

// Additional includes (if needed)
// For example, include Lexer header if you plan to use Lexer utilities:
// #include "clang/Lex/Lexer.h"

//------------------------------------------------------------------------------
// Customize program states: Register a map to track freed objects.
//------------------------------------------------------------------------------
REGISTER_MAP_WITH_PROGRAMSTATE(FreedObjectMap, const MemRegion*, bool)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Use-after-free", "Memory Error")) {}

  // Callback: Check after a call is processed.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Callback: Check each memory location load/store.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  // Helper function to report use-after-free bug.
  void reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Using utility function to check if the call is to "mptcp_close_ssk"
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "mptcp_close_ssk", C))
    return;

  // Ensure there are enough arguments: we expect at least 3 arguments.
  if (Call.getNumArgs() < 3)
    return;

  // Retrieve the subflow pointer (argument index 2)
  SVal SubflowVal = Call.getArgSVal(2);
  const MemRegion *MR = SubflowVal.getAsRegion();
  if (!MR)
    return;

  // Get the base region from MR
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Mark the subflow as freed in our state map.
  State = State->set<FreedObjectMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // For memory accesses, get the corresponding memory region.
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Check if this region was previously marked as freed.
  const bool *FreedFlag = State->get<FreedObjectMap>(MR);
  if (FreedFlag && *FreedFlag) {
    reportUseAfterFree(MR, S, C);
  }
}

void SAGenTestChecker::reportUseAfterFree(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  // Generate a non fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create a bug report with a concise message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use-after-free: reading a field of a freed subflow object", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use-after-free read of a field from a subflow object after mptcp_close_ssk() frees it",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
