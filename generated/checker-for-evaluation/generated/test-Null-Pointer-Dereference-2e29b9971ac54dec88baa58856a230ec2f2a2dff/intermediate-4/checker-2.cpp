#include "clang/AST/Expr.h"
#include "clang/Basic/LangOptions.h"
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
#include "llvm/ADT/StringRef.h"

#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: Map a memory region to the allocated field name.
// When a call to kzalloc is bound to a member expression on field "sve_state",
// we record this mapping.
// Changed llvm::StringRef to std::string to satisfy the Profile API.
REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedFieldMap, const MemRegion*, std::string)

namespace {

class SAGenTestChecker 
  : public Checker< check::Bind, check::BranchCondition > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Incorrect null pointer check after kzalloc")) {}

  // Callback: track pointer-binding events.
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

  // Callback: intercept if-statement conditions.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // (Optional) You can add additional helper functions here if needed.
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  // We need S to be valid.
  if (!S)
    return;

  // Cast S to an expression so we can call IgnoreImplicit().
  const Expr *Ex = dyn_cast<Expr>(S);
  if (!Ex)
    return;

  // Check if the left-hand side (LHS) of the assignment is a member expression
  // that refers to "sve_state".
  const MemberExpr *ME = dyn_cast<MemberExpr>(Ex->IgnoreImplicit());
  if (!ME)
    return;

  if (!ExprHasName(ME, "sve_state", C))
    return;

  // Look downward in the AST starting from S to see if there is a call expression.
  const CallExpr *CE = findSpecificTypeInChildren<CallExpr>(S);
  if (!CE)
    return;

  // Verify that the call is to kzalloc.
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (FD->getNameAsString() != "kzalloc")
      return;
  } else {
    return;
  }

  // Retrieve the memory region corresponding to the LHS expression.
  const MemRegion *MR = getMemRegionFromExpr(ME, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  // Record in our program state that this region is allocated for "sve_state".
  ProgramStateRef State = C.getState();
  State = State->set<AllocatedFieldMap>(MR, std::string("sve_state"));
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;
    
  ProgramStateRef State = C.getState();
  
  // Cast Condition to an Expr so we can call ExprHasName().
  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  // If the condition (e.g., the null check) contains "za_state", it appears to be
  // checking the wrong field.
  if (ExprHasName(CondExpr, "za_state", C)) {
    // Additionally, check if we previously recorded an allocation for "sve_state".
    bool FoundSveState = false;
    // Retrieve the immutable map of AllocatedFieldMap from the program state.
    const auto &AllocatedFields = State->get<AllocatedFieldMap>();
    for (auto I = AllocatedFields.begin(), E = AllocatedFields.end(); I != E; ++I) {
      // I->second returns the stored field name.
      if (I->second == "sve_state") {
        FoundSveState = true;
        break;
      }
    }
    if (FoundSveState) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (N) {
        auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Incorrect null check: expected 'sve_state' to be checked after kzalloc", N);
        Report->addRange(Condition->getSourceRange());
        C.emitReport(std::move(Report));
      }
    }
  }
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects an incorrect null pointer check where kzalloc() allocated memory for "
      "'sve_state' but the check is performed on 'za_state'",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
