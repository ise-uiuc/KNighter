#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
// Removed the Taint.h include as it does not exist in Clang-18.
// #include "clang/StaticAnalyzer/Core/Checkers/Taint.h"
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

REGISTER_MAP_WITH_PROGRAMSTATE(QueueXefMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Initialization Ordering Error",
                                        "Resource Registration")) {}

  // Callback: Called after a function call is evaluated.
  // We check for a call to xa_alloc.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
  // Callback: Called when a binding (assignment) occurs.
  // We check for assignments to the "xef" member of a queue.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportOrderingError(const CallEvent &Call, CheckerContext &C, const MemRegion *QueueReg) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Use the utility function to check the function name accurately.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Check if the call is to "xa_alloc".
  if (!ExprHasName(OriginExpr, "xa_alloc", C))
    return;

  // In our target code, the third argument (index 2) is the queue pointer.
  if (Call.getNumArgs() < 3)
    return;
  
  SVal QueueArgVal = Call.getArgSVal(2);
  const MemRegion *QueueReg = QueueArgVal.getAsRegion();
  if (!QueueReg)
    return;
  
  // Get the base region for proper pointer analysis.
  QueueReg = QueueReg->getBaseRegion();
  if (!QueueReg)
    return;

  // Check whether the queue's "xef" field has been set.
  const bool *XefSet = State->get<QueueXefMap>(QueueReg);
  
  // If the "xef" field is not yet set, then xa_alloc is invoked too early.
  if (!XefSet || !(*XefSet)) {
    reportOrderingError(Call, C, QueueReg);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (!StoreE)
    return;

  // Cast the store statement to an expression to use IgnoreImpCasts().
  const Expr *StoreExpr = dyn_cast<Expr>(StoreE);
  if (!StoreExpr)
    return;
  
  // Check if the binding (assignment) is to a member expression.
  const MemberExpr *ME = dyn_cast<MemberExpr>(StoreExpr->IgnoreImpCasts());
  if (!ME)
    return;

  // Check whether the member being assigned is "xef".
  if (ME->getMemberDecl()->getNameAsString() != "xef")
    return;

  // Obtain the base region of the object whose "xef" field is being set.
  const Expr *BaseExpr = ME->getBase()->IgnoreImpCasts();
  if (!BaseExpr)
    return;

  const MemRegion *BaseReg = getMemRegionFromExpr(BaseExpr, C);
  if (!BaseReg)
    return;
  BaseReg = BaseReg->getBaseRegion();
  if (!BaseReg)
    return;

  // Update the program state to mark that the object's "xef" field has been set.
  State = State->set<QueueXefMap>(BaseReg, true);
  C.addTransition(State);
}

void SAGenTestChecker::reportOrderingError(const CallEvent &Call, CheckerContext &C, const MemRegion *QueueReg) const {
  // Generate an error node if possible.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Resource registration ordering issue: xa_alloc called before initializing q->xef", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects resource registration ordering bug: q->xef is set after xa_alloc", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
