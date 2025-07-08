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
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

// Customize program states: We define a trait that holds a bool flag indicating
// whether a bounds-check against __DML2_WRAPPER_MAX_STREAMS_PLANES__ has been performed.
REGISTER_TRAIT_WITH_PROGRAMSTATE(BoundsChecked, bool)

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker :
  public Checker< check::BeginFunction,
                  check::BranchCondition,
                  check::PreStmt<ArraySubscriptExpr> > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unchecked array index", "Buffer Overflow")) {}

  // Called when beginning the analysis of a function.
  void checkBeginFunction(CheckerContext &C) const {
    // Restrict the analysis to the target function "map_hw_resources".
    const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
    if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
      if (FD->getName() == "map_hw_resources") {
        ProgramStateRef State = C.getState();
        State = State->set<BoundsChecked>(false);
        C.addTransition(State);
      }
    }
  }

  // Called when a branch condition is evaluated.
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    // We check the condition statement's source text to see if it
    // contains the macro __DML2_WRAPPER_MAX_STREAMS_PLANES__.
    // If found, we mark the state as having performed a bounds-check.
    ProgramStateRef State = C.getState();
    const Expr *CondE = dyn_cast<Expr>(Condition);
    if (!CondE)
      return;
    
    if (ExprHasName(CondE, "__DML2_WRAPPER_MAX_STREAMS_PLANES__", C)) {
      State = State->set<BoundsChecked>(true);
    }
    C.addTransition(State);
  }

  // Called before an ArraySubscriptExpr is executed.
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // We get the base expression of the array subscript.
    const Expr *BaseExpr = ASE->getBase()->IgnoreParenCasts();
    if (!BaseExpr)
      return;
    // Check if the base expression's source text contains one
    // of our suspicious destination array names.
    if (ExprHasName(BaseExpr, "dml_pipe_idx_to_stream_id", C) ||
        ExprHasName(BaseExpr, "dml_pipe_idx_to_plane_id", C)) {
      // If a bounds-check was performed in the code (i.e. the flag is true),
      // then this access has already been guarded.
      bool Checked = State->get<BoundsChecked>();
      if (Checked)
        return;
      // If not, then report a potential buffer overflow bug.
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unchecked array index may cause a buffer overflow.", N);
      C.emitReport(std::move(report));
    }
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Warns when an array index is used without checking against __DML2_WRAPPER_MAX_STREAMS_PLANES__, which may lead to a buffer overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
