#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
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
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;

namespace {

// Helper: Search upward in the AST for a function declaration.
template <typename T>
static const T *findSpecificTypeInParentsHelper(const Stmt *S,
                                                  CheckerContext &C) {
  const ExplodedNode *Pred = C.getPredecessor();
  while (Pred) {
    const ProgramPoint &PP = Pred->getLocation();
    if (auto PreStmtOpt = PP.getAs<PreStmt>()) {
      if (const T *Found = dyn_cast_or_null<T>(*PreStmtOpt))
        return Found;
    }
    Pred = Pred->getFirstPred();
  }
  return nullptr;
}

// This helper tries to find a DeclRefExpr with the given name in the parents
// of the given statement.
static const DeclRefExpr *findDeclRefWithNameInParents(const Stmt *S,
                                                       StringRef Name,
                                                       CheckerContext &C) {
  const ExplodedNode *Pred = C.getPredecessor();
  while (Pred) {
    const ProgramPoint &PP = Pred->getLocation();
    if (auto PreStmtOpt = PP.getAs<PreStmt>()) {
      if (const DeclRefExpr *DRE = dyn_cast_or_null<DeclRefExpr>(*PreStmtOpt)) {
        if (ExprHasName(DRE, Name, C))
          return DRE;
      }
    }
    Pred = Pred->getFirstPred();
  }
  return nullptr;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  // Constructor: our checker looks for unchecked use of copy_from_sockptr.
  SAGenTestChecker() : BT(new BugType(this, "Unchecked copy_from_sockptr",
                                        "Kernel Bounds Checking")) {}

  // This callback is invoked before a function call is evaluated.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper function to report the bug.
  void reportUncheckedCopy(CheckerContext &C, const CallEvent &Call) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Only interested in calls to copy_from_sockptr.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  
  // Use utility function to check function name accurately.
  if (!ExprHasName(OriginExpr, "copy_from_sockptr", C))
    return;

  // We expect the call to have at least three arguments:
  // arg0: destination pointer
  // arg1: source sockptr
  // arg2: fixed copy size (the required size)
  if (Call.getNumArgs() < 3)
    return;

  // Evaluate the fixed copy size from the third argument.
  llvm::APSInt ExpectedSize;
  const Expr *SizeExpr = Call.getArgExpr(2);
  if (!EvaluateExprToInt(ExpectedSize, SizeExpr, C))
    return;

  // Walk upward from the call site to locate the function parameter "optlen".
  // This assumes that the parameter optlen is used in the vicinity of the call.
  const DeclRefExpr *OptlenDRE = findDeclRefWithNameInParents(OriginExpr, "optlen", C);
  if (!OptlenDRE)
    return;

  // Retrieve the symbolic value of optlen.
  SVal OptlenVal = C.getState()->getSVal(OptlenDRE, C.getLocationContext());
  SymbolRef OptlenSym = OptlenVal.getAsSymbol();
  if (!OptlenSym)
    return;

  // Infer the maximal value of optlen.
  const llvm::APSInt *MaxOptlen = inferSymbolMaxVal(OptlenSym, C);
  if (!MaxOptlen)
    return;

  // If the maximum possible value of optlen is less than the fixed copy size,
  // the copy_from_sockptr call may copy more data than the user-supplied length.
  if (MaxOptlen->getExtValue() < ExpectedSize.getExtValue()) {
    reportUncheckedCopy(C, Call);
  }
}

void SAGenTestChecker::reportUncheckedCopy(CheckerContext &C, const CallEvent &Call) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
    
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked copy_from_sockptr: optlen may be too small", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker", 
      "Detects fixed-size copying using copy_from_sockptr without validating user-supplied buffer length", 
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
