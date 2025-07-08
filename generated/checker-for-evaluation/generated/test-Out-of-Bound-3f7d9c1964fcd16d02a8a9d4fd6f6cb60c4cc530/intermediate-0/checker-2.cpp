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

// Additional necessary includes.
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include <optional>  // Replaced llvm/ADT/Optional.h with standard <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program state: Register a trait to track whether the hash key length has been checked.
// The default value is false (i.e., not validated).
REGISTER_TRAIT_WITH_PROGRAMSTATE(HashKeyChecked, bool)

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unvalidated hash key length")) {}

  // Callback to intercept branch conditions.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // Attempt to treat the condition as an expression.
    const Expr *CondExpr = dyn_cast<Expr>(Condition);
    if (!CondExpr) {
      C.addTransition(State);
      return;
    }
    CondExpr = CondExpr->IgnoreParenCasts();

    // Look for a binary operator ">".
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondExpr)) {
      if (BO->getOpcode() == BO_GT) {
        const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
        // Use the helper utility ExprHasName to check if one operand is "rss_key_size"
        // and the other is "VIRTIO_NET_RSS_MAX_KEY_SIZE".
        if (ExprHasName(LHS, "rss_key_size", C) &&
            ExprHasName(RHS, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C)) {
          // Mark the hash key check as performed.
          State = State->set<HashKeyChecked>(true);
          C.addTransition(State);
          return;
        }
      }
    }
    C.addTransition(State);
  }

  // Callback to intercept function calls.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // Use the origin expr's source text to identify rss_indirection_table_alloc calls.
    const Expr *OriginExpr = Call.getOriginExpr();
    if (!OriginExpr || !ExprHasName(OriginExpr, "rss_indirection_table_alloc", C))
      return;
      
    // Retrieve the flag from the program state. If it is false, no validation was performed.
    bool WasChecked = false;
    std::optional<bool> CheckedOpt = State->get<HashKeyChecked>();
    if (CheckedOpt) {
      WasChecked = *CheckedOpt;
    }
    
    // If the hash key length was not validated prior to this critical call, report an error.
    if (!WasChecked) {
      ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
      if (!ErrNode)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unvalidated hash key length may lead to out-of-bound access.", ErrNode);
      C.emitReport(std::move(Report));
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects use of a hash key length without proper validation", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
