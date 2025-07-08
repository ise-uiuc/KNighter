// /scratch/chenyuan-data/SAGEN/result-0224-bugfail-multi-o3mini/test-Concurrency-5e700b384ec13f5bcac9855cb28fcc674f1d3593/checkers/checker0.cpp
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

// Customize Program State: Define a boolean flag to track if client ops have been set.
// "ClientOpsSet" is false by default (i.e. absent from the ProgramState means false).
REGISTER_TRAIT_WITH_PROGRAMSTATE(ClientOpsSet, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Initialization Order Bug")) {}

  // Callback for function calls within a function.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // Callback when finishing a function.
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // (Optional) Helper could be added if more functionality is needed.
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Only track calls made within the function 'cros_ec_uart_probe'
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getNameAsString() != "cros_ec_uart_probe")
    return;

  // Retrieve the originating expression.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if the call is to serdev_device_set_client_ops.
  if (ExprHasName(OriginExpr, "serdev_device_set_client_ops", C)) {
    // Mark the program state flag "ClientOpsSet" as true.
    State = State->set<ClientOpsSet>(true);
    C.addTransition(State);
  }

  // Check if the call is to devm_serdev_device_open.
  if (ExprHasName(OriginExpr, "devm_serdev_device_open", C)) {
    // Retrieve the current flag. Interpreting missing as false.
    bool ClientOpsAreSet = State->get<ClientOpsSet>();
    if (!ClientOpsAreSet) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Device opened before client operations set", N);
      C.emitReport(std::move(Report));
    }
  }

  // Optionally: Further calls like serdev_device_set_baudrate or 
  // serdev_device_set_flow_control can be checked similarly.
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // When the function finishes, clear our program state flag.
  ProgramStateRef State = C.getState();
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (FD && FD->getNameAsString() == "cros_ec_uart_probe") {
    State = State->remove<ClientOpsSet>();
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects incorrect initialization order: devm_serdev_device_open called before client ops are set",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
