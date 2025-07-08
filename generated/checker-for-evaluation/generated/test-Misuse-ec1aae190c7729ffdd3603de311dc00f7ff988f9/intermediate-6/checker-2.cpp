#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
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
#include <memory>

using namespace clang;
using namespace ento;

// Customize program states:
// Map each event object (its base MemRegion) to a bool flag, which is true
// if its counter field "datalen" has been updated; false otherwise.
REGISTER_MAP_WITH_PROGRAMSTATE(FlexDatalenUpdateMap, const MemRegion *, bool)

// The checker will use two callbacks:
//   - checkBind: To track when the datalen field is updated.
//   - checkPostCall: To intercept memcpy calls and check the order.
namespace {

class SAGenTestChecker : public Checker<check::Bind, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker()
      : BT(new BugType(this, "Flexible array access ordering",
                         "The flexible array 'data' is accessed before its counter 'datalen' is updated")) {}

  // Callback: Track field binding assignments.
  // When an assignment is performed to a field named "datalen", mark the event object as updated.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
    if (!StoreE)
      return;
    
    // Using the utility function ExprHasName to see if the left-hand side includes "datalen"
    if (ExprHasName(cast<Expr>(StoreE), "datalen", C)) {
      // Retrieve the memory region corresponding to the left-hand side.
      const MemRegion *MR = getMemRegionFromExpr(cast<Expr>(StoreE), C);
      if (!MR)
        return;
      MR = MR->getBaseRegion();
      if (!MR)
        return;
      
      ProgramStateRef State = C.getState();
      // Mark that the datalen field on this event object has been updated.
      State = State->set<FlexDatalenUpdateMap>(MR, true);
      C.addTransition(State);
    }
  }

  // Callback: After a function call is complete.
  // We intercept memcpy calls to check if the destination is the flexible array "data"
  // of an event object whose counter field has not yet been updated.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    // Get the origin expression for the call.
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr)
      return;
    
    // Check if the called function is memcpy.
    if (!ExprHasName(OriginExpr, "memcpy", C))
      return;
      
    // Attempt to get the CallExpr for memcpy.
    const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
    if (!CE)
      return;
      
    if (CE->getNumArgs() < 1)
      return;
      
    // We assume memcpy(dest, src, size); we are interested in the destination argument.
    const Expr *DestArg = CE->getArg(0)->IgnoreParenImpCasts();
    if (!DestArg)
      return;
    
    // Check if this destination expression appears to be the flexible-array member "data".
    if (!ExprHasName(DestArg, "data", C))
      return;
      
    // Retrieve the memory region of the destination.
    const MemRegion *DestMR = getMemRegionFromExpr(DestArg, C);
    if (!DestMR)
      return;
    DestMR = DestMR->getBaseRegion();
    if (!DestMR)
      return;
    
    ProgramStateRef State = C.getState();
    // Look up whether the corresponding event object has its field "datalen" updated.
    const bool *Updated = State->get<FlexDatalenUpdateMap>(DestMR);
    // If not updated, then the memcpy happened before updating datalen.
    if (!Updated || !(*Updated)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Flexible array 'data' accessed before its counter 'datalen' is updated", N);
      Report->addRange(DestArg->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects when a flexible array member is accessed before its counter field is updated",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
