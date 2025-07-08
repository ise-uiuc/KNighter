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
#include "clang/Lex/Lexer.h"  // For source text extraction

using namespace clang;
using namespace ento;
using namespace taint;

// Register a pointer-alias program state map to track relationships
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

//---------------------------------------------------------------------------
// Checker Implementation for detecting an atomicity violation in which the
// shared pointer "urb->hcpriv" is set to NULL outside a critical section.
//---------------------------------------------------------------------------
namespace {

class SAGenTestChecker : public Checker<check::Bind, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Atomicity Violation")) {}

  // This callback is invoked when a binding (assignment) is performed.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Optional: This callback is invoked before a call is executed.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper to report an atomicity violation bug.
  void reportAtomicityViolation(const Stmt *S, CheckerContext &C, StringRef Msg) const;
};

/// reportAtomicityViolation - Helper to generate a non-fatal error node and
/// report the bug with a concise message.
void SAGenTestChecker::reportAtomicityViolation(const Stmt *S, CheckerContext &C,
                                                  StringRef Msg) const {
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    Report->addRange(S->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

/// checkBind - Invoked when a value is bound to a memory region. We check if the
/// left-hand side (LHS) of the assignment involves "hcpriv" and if the assignment
/// assigns a NULL constant. If so, we traverse upward in the AST to see whether this
/// assignment occurs under a lock (e.g. inside a call to spin_lock_irqsave). If not,
/// we report an atomicity violation.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                   CheckerContext &C) const {
  // First, ensure we have a valid store expression.
  if (!StoreE)
    return;

  // Check if the RHS is a NULL constant.
  // Note: isZeroConstant() returns true if the value is known to be zero.
  if (!Val.isZeroConstant())
    return;

  // Use the utility function to check if the source text of the assignment contains "hcpriv".
  // This will help us filter assignments to the shared pointer "urb->hcpriv".
  if (!ExprHasName(cast<Expr>(StoreE), "hcpriv", C))
    return;

  // Now, use the utility function to traverse upward in the AST to find an enclosing call to a lock primitive.
  const CallExpr *LockCall = findSpecificTypeInParents<CallExpr>(StoreE, C);
  bool FoundSpinLock = false;
  if (LockCall) {
    // Check if the call's source text contains "spin_lock_irqsave".
    if (ExprHasName(LockCall, "spin_lock_irqsave", C))
      FoundSpinLock = true;
  }

  // If no lock acquisition was found in the AST parents, this assignment is suspect.
  if (!FoundSpinLock) {
    reportAtomicityViolation(StoreE, C,
      "Atomicity Violation: shared pointer modified (set to NULL) outside lock");
  }

  // Optionally, record aliasing information (not used further in this simple implementation).
  ProgramStateRef State = C.getState();
  if (const MemRegion *Region = Loc.getAsRegion()) {
    // Bind the region with itself in a simple alias map.
    State = State->set<PtrAliasMap>(Region, Region);
    C.addTransition(State);
  }
}

/// checkPreCall - Optional callback to intercept calls that operate on "urb->hcpriv".
/// Here we check calls to functions such as "dwc2_hcd_urb_dequeue" and ensure that the
/// pointer argument is not NULL. If it is, then it likely was modified outside a lock.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  // Use a precise check on the source text.
  if (!ExprHasName(OriginExpr, "dwc2_hcd_urb_dequeue", C))
    return;
  // According to the bug pattern, urb->hcpriv is passed as the second argument.
  if (Call.getNumArgs() < 2)
    return;

  SVal Arg = Call.getArgSVal(1);
  // If the argument is a null constant, it is indicative of the bug.
  if (Arg.isZeroConstant()) {
    reportAtomicityViolation(OriginExpr, C,
      "Atomicity Violation: shared pointer used in dwc2_hcd_urb_dequeue is NULL");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects an atomicity violation where a shared pointer (urb->hcpriv) is set to NULL outside critical section",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
