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
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are needed.

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Wrong devlink cmd in dump",
                       "Linux Kernel API Misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  static bool isDumpContext(const FunctionDecl *FD);
};

bool SAGenTestChecker::isDumpContext(const FunctionDecl *FD) {
  if (!FD)
    return false;
  StringRef Name = FD->getName();
  // Heuristic: dump handlers in the kernel typically contain "dump" in the name
  // (e.g., devlink_nl_port_get_dump_one, dumpit). This confines our check.
  return Name.contains("dump");
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // We only care about calls to devlink_nl_port_fill
  if (!ExprHasName(Origin, "devlink_nl_port_fill", C))
    return;

  // Ensure we are inside a dump-like handler to avoid false positives
  const auto *FD =
      dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!isDumpContext(FD))
    return;

  // The 'cmd' argument is the 3rd arg (index 2)
  if (Call.getNumArgs() <= 2)
    return;

  const Expr *CmdArg = Call.getArgExpr(2);
  if (!CmdArg)
    return;

  // Detect misuse: DEVLINK_CMD_NEW used instead of DEVLINK_CMD_PORT_NEW.
  // Note: ExprHasName performs a substring match, so we must ensure we do not
  // match DEVLINK_CMD_PORT_NEW inadvertently.
  bool UsesWrongCmd =
      ExprHasName(CmdArg, "DEVLINK_CMD_NEW", C) &&
      !ExprHasName(CmdArg, "DEVLINK_CMD_PORT_NEW", C);

  if (!UsesWrongCmd)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Wrong devlink cmd in dump: use DEVLINK_CMD_PORT_NEW", N);
  R->addRange(CmdArg->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects devlink port dump using DEVLINK_CMD_NEW instead of DEVLINK_CMD_PORT_NEW",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
