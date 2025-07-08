#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
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

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: Map a queue object's region to a boolean value.
// 'true' means the queue has been secured (i.e. its xef field has been set via xe_file_get),
// 'false' or not set means it is not yet secured.
REGISTER_MAP_WITH_PROGRAMSTATE(SecuredMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(new BugType(this, "Handle allocated before object secured")) {}

  // Callback invoked when a value is bound to a memory region.
  // We use this to flag the queue object as secured when its xef field is assigned.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
    // Look for a call to "xe_file_get" within the binding statement.
    // We search the children of the binding statement.
    const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
    if (!CE)
      return;
    // Use utility function to check if the call originates from "xe_file_get".
    if (!ExprHasName(CE, "xe_file_get", C))
      return;

    // Retrieve the memory region corresponding to the left-hand side of the binding.
    const MemRegion *MR = Loc.getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;

    ProgramStateRef State = C.getState();
    State = State->set<SecuredMap>(MR, true);
    C.addTransition(State);
  }

  // Callback invoked after a function call.
  // We use this to intercept calls to "xa_alloc", and then check
  // whether the queue object (third argument) has been secured.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    // Get the origin expression of the call.
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;
    // Check if this call is to xa_alloc.
    if (!ExprHasName(OriginExpr, "xa_alloc", C))
      return;

    // Expect the third argument (index 2) to be the pointer to the queue object.
    if (Call.getNumArgs() <= 2)
      return;
    const Expr *QueueArg = Call.getArgExpr(2);
    if (!QueueArg)
      return;
    const MemRegion *MR = getMemRegionFromExpr(QueueArg, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;

    ProgramStateRef State = C.getState();
    // Lookup the secured flag for this queue object.
    const bool *Secured = State->get<SecuredMap>(MR);
    // If the queue is not flagged as secured, report the bug.
    if (!Secured || (*Secured == false)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "xa_alloc used before the queue object is secured via xe_file_get",
            N);
      Report->addRange(OriginExpr->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects exposing a new handle before the underlying object is secured (i.e. before xe_file_get is called)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
