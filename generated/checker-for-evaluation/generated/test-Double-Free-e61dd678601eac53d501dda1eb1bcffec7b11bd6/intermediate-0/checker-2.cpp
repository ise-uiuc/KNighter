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
#include "clang/AST/ASTContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Customize program states:
// A map to track whether a given memory region has been freed already.
REGISTER_MAP_WITH_PROGRAMSTATE(DoubleFreeMap, const MemRegion *, bool)
// A trait to record whether bch2_dev_buckets_free has been called in the current function.
REGISTER_TRAIT_WITH_PROGRAMSTATE(BucketsFreeCalled, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Double free", "Double Free Issue")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Retrieve the origin expression for the call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Check if the callee is "bch2_dev_buckets_free" and mark BucketsFreeCalled as true.
  if (ExprHasName(OriginExpr, "bch2_dev_buckets_free", C)) {
    // Mark that bch2_dev_buckets_free has been called.
    State = State->set<BucketsFreeCalled>(true);
    C.addTransition(State);
  }

  // Check if the function called is "kfree".
  if (ExprHasName(OriginExpr, "kfree", C)) {
    // Check if the argument (index 0) contains "buckets_nouse".
    const Expr *ArgExpr = Call.getArgExpr(0);
    if (!ArgExpr)
      return;
    if (!ExprHasName(ArgExpr, "buckets_nouse", C))
      return;

    // Retrieve the memory region corresponding to the argument.
    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    if (!MR)
      return;

    // Check state: see if this region was already freed.
    const bool *AlreadyFreed = State->get<DoubleFreeMap>(MR);
    bool BucketsFreeCalledFlag = State->get<BucketsFreeCalled>();

    // If already freed or if bch2_dev_buckets_free has been called,
    // emit a bug report since the resource will be freed twice.
    if ((AlreadyFreed && *AlreadyFreed) || BucketsFreeCalledFlag) {
      reportDoubleFree(Call, C);
    } else {
      // Mark the region as freed.
      State = State->set<DoubleFreeMap>(MR, true);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Optionally, check at end of function if bch2_dev_buckets_free has been called.
  ProgramStateRef State = C.getState();
  if (State->get<BucketsFreeCalled>())
    C.addTransition(State);
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "Double free of buckets_nouse", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of buckets_nouse by kfree when bch2_dev_buckets_free is also freeing it",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
