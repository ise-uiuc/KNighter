#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/MemberExpr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclBase.h"
#include "clang/AST/Type.h"
#include "clang/Frontend/CheckerRegistry.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Register a program state map to track the initialization state of "num_trips" field.
// The key is the MemRegion corresponding to the "num_trips" field; the value is true if initialized.
REGISTER_MAP_WITH_PROGRAMSTATE(InitFieldMap, const MemRegion*, bool)
// Optionally, track aliasing for the field.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker 
  : public Checker<check::PreCall, check::Bind> {
  
  mutable std::unique_ptr<BugType> BT;
  
public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Uninitialized field use", "Memory Copy Argument")) {}

  // Callback: checkPreCall is invoked before a call is evaluated.
  // We intercept memcpy calls here to verify whether the size argument uses an uninitialized "num_trips" field.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  
  // Callback: checkBind is invoked when a value is bound to a memory region.
  // We use it to detect assignments that initialize the "num_trips" field.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

private:
  // Helper function to report bugs.
  void reportUninitField(const CallEvent &Call, const MemRegion *FieldRegion, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // Check if the store expression is a field access.
  // We are interested in assignments to a field named "num_trips".
  if (!StoreE)
    return;
  
  const MemberExpr *ME = dyn_cast<MemberExpr>(StoreE);
  if (!ME)
    return;
  
  // Check if the member name is "num_trips".
  if (ME->getMemberNameInfo().getAsString() != "num_trips")
    return;
  
  // Retrieve the memory region corresponding to the "num_trips" field.
  const MemRegion *FieldRegion = getMemRegionFromExpr(ME, C);
  if (!FieldRegion)
    return;
  
  FieldRegion = FieldRegion->getBaseRegion();
  if (!FieldRegion)
    return;
  
  // Mark the field as initialized in the program state.
  ProgramStateRef State = C.getState();
  State = State->set<InitFieldMap>(FieldRegion, true);
  
  // Optionally update aliasing information.
  // For simplicity, we record an alias from this field to itself.
  State = State->set<PtrAliasMap>(FieldRegion, FieldRegion);
  
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // We are only interested in memcpy calls.
  const Expr *OriginE = Call.getOriginExpr();
  if (!OriginE)
    return;
  
  // Use utility function ExprHasName to check if the source text of the call contains "memcpy".
  // However, to be more robust, we get the callee identifier.
  const Expr *CalleeExpr = Call.getCalleeNameExpr();
  if (!CalleeExpr)
    return;
    
  if (!ExprHasName(CalleeExpr, "memcpy", C))
    return;
  
  // Ensure memcpy has at least 3 arguments.
  if (Call.getNumArgs() < 3)
    return;
  
  // We are interested in the third argument (index 2), which represents the size.
  // Check if it uses the "num_trips" field.
  const Expr *SizeArg = Call.getArgExpr(2);
  if (!SizeArg)
    return;
  
  // Use utility function ExprHasName to search for "num_trips" within the size argument.
  if (!ExprHasName(SizeArg, "num_trips", C))
    return;
  
  // Extract the memory region corresponding to the "num_trips" field usage.
  const MemRegion *FieldRegion = getMemRegionFromExpr(SizeArg, C);
  if (!FieldRegion)
    return;
  
  FieldRegion = FieldRegion->getBaseRegion();
  if (!FieldRegion)
    return;

  // Check program state map for initialization status.
  ProgramStateRef State = C.getState();
  const bool *InitFlag = State->get<InitFieldMap>(FieldRegion);
  // If the field is not marked as initialized, report a bug.
  if (!InitFlag || !(*InitFlag)) {
    reportUninitField(Call, FieldRegion, C);
  }
}

void SAGenTestChecker::reportUninitField(const CallEvent &Call, const MemRegion *FieldRegion, CheckerContext &C) const {
  // Generate a non-fatal error node.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  
  // Create a bug report with a concise message.
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Uninitialized 'num_trips' used as size argument in memcpy", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects memcpy calls that use an uninitialized num_trips field as the size argument", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
