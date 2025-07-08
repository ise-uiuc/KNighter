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
#include <string>
#include "llvm/ADT/FoldingSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Add a specialization for std::string to support profiling in ProgramState maps.
// This allows the REGISTER_MAP_WITH_PROGRAMSTATE macro to work with std::string values.
namespace clang {
namespace ento {
  template <>
  struct ProgramStateTrait<std::string> {
    static void Profile(const std::string &Val, llvm::FoldingSetNodeID &ID) {
      ID.AddString(Val);
    }
  };
}
} // end namespace clang::ento

// Customize program state: Map a memory region to the expected field name.
// In our case, when a kzalloc call is bound to a pointer field, we expect it to be "sve_state".
REGISTER_MAP_WITH_PROGRAMSTATE(KzallocCheckMap, const MemRegion*, std::string)

namespace {

class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
  // BugType describing our error.
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Incorrect NULL check after kzalloc")) {}

  // Callback when a value is bound to a memory location.
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

  // Callback for conditions in branching statements.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportWrongNullCheck(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  // Cast StoreE to an Expr* since we need to use expression utilities.
  const Expr *StoreEExpr = dyn_cast_or_null<Expr>(StoreE);
  if (!StoreEExpr)
    return;

  // Check if the statement (RHS) is a call expression.
  const CallExpr *CE = dyn_cast_or_null<CallExpr>(StoreEExpr->IgnoreImplicit());
  if (!CE)
    return;

  // Using utility function to check if this call is to "kzalloc".
  if (!ExprHasName(CE, "kzalloc", C))
    return;

  // Retrieve the memory region associated with the LHS (wrapped as an Expr).
  const MemRegion *Region = getMemRegionFromExpr(StoreEExpr, C);
  if (!Region)
    return;
  Region = Region->getBaseRegion();
  if (!Region)
    return;

  // Check the LHS source text to determine the field name.
  // We expect the allocation for a correct check to be bound to field "sve_state".
  if (ExprHasName(StoreEExpr, "sve_state", C)) {
    ProgramStateRef State = C.getState();
    State = State->set<KzallocCheckMap>(Region, "sve_state");
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *ConditionExpr = dyn_cast_or_null<Expr>(Condition);
  if (!ConditionExpr)
    return;

  ProgramStateRef State = C.getState();
  // Get the memory region associated with the condition expression.
  const MemRegion *Region = getMemRegionFromExpr(ConditionExpr, C);
  if (!Region)
    return;
  Region = Region->getBaseRegion();
  if (!Region)
    return;

  // Check if this region was recorded during a kzalloc binding.
  const std::string *ExpectedField = State->get<KzallocCheckMap>(Region);
  if (!ExpectedField)
    return;

  // Now, examine the condition's source text.
  // The condition should check the correct field, e.g., "sve_state".
  if (!ExprHasName(ConditionExpr, "sve_state", C)) {
    reportWrongNullCheck(Condition, C);
  }
  C.addTransition(State);
}

void SAGenTestChecker::reportWrongNullCheck(const Stmt *Condition, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Incorrect NULL check: expected check on 'sve_state'", N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects incorrect NULL check after kzalloc: the wrong field is checked", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
