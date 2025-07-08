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
#include "clang/Lex/Lexer.h"  // For getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: Register a map to track if an exec_queue object is safe
REGISTER_MAP_WITH_PROGRAMSTATE(SafeExecQueueMap, const MemRegion*, bool)

// Optional: If you want to track pointer aliasing, you can register a PtrAliasMap
// REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;  
public:
  SAGenTestChecker() : BT(new BugType(this, "ID allocated before object secured")) {}

  // Callback function: checkPostCall will monitor calls to xe_file_get and xa_alloc.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
private:
  // Helper function to report the bug
  void reportBug(const CallEvent &Call, CheckerContext &C, const Expr *Origin) const;
};

void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C,
                                 const Expr *Origin) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  // Use PathSensitiveBugReport constructor that takes an ExplodedNode pointer.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "User-accessible ID allocated before exec_queue is secured (xe_file_get not called)", N);
  Report->addRange(Origin->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;
  
  // Check if the call is to xe_file_get.
  if (ExprHasName(Origin, "xe_file_get", C)) {
    // Retrieve the memory region from the call expression.
    const MemRegion *MR = getMemRegionFromExpr(Origin, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    State = State->set<SafeExecQueueMap>(MR, true);
    C.addTransition(State);
    return;
  }
  
  // Check if the call is to xa_alloc.
  if (ExprHasName(Origin, "xa_alloc", C)) {
    // According to the bug pattern, the third argument (index 2) is the exec_queue pointer.
    if (Call.getNumArgs() <= 2)
      return;
    SVal Arg = Call.getArgSVal(2);
    const MemRegion *MR = Arg.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    const bool *Secured = State->get<SafeExecQueueMap>(MR);
    if (!Secured || !(*Secured)) {
      // The exec_queue object has not been secured by xe_file_get.
      reportBug(Call, C, Origin);
    }
    C.addTransition(State);
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects exposure of a user-accessible ID (via xa_alloc) before the "
      "corresponding exec_queue is secured by xe_file_get", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
