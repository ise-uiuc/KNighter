```cpp
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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track device base objects whose buckets_nouse have been freed
REGISTER_SET_WITH_PROGRAMSTATE(ManualFreedBucketsNouse, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(HighLevelFreedBucketsNouse, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free of member", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static bool isKfree(const CallEvent &Call, CheckerContext &C);
      static bool isBucketsHLFree(const CallEvent &Call, CheckerContext &C);

      const MemRegion *getOwnerRegionIfMember(const Expr *Arg, StringRef MemberName,
                                              CheckerContext &C) const;

      const MemRegion *getArgBaseRegion(const CallEvent &Call, unsigned Idx,
                                        CheckerContext &C) const;

      void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

// Determine if the call is to kfree(...)
bool SAGenTestChecker::isKfree(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "kfree", C);
}

// Determine if the call is to bch2_dev_buckets_free(ca)
bool SAGenTestChecker::isBucketsHLFree(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "bch2_dev_buckets_free", C);
}

// If Arg contains a MemberExpr accessing the specified member, return the base object's region.
const MemRegion *SAGenTestChecker::getOwnerRegionIfMember(const Expr *Arg, StringRef MemberName,
                                                          CheckerContext &C) const {
  if (!Arg)
    return nullptr;

  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg);
  if (!ME)
    return nullptr;

  const ValueDecl *MD = ME->getMemberDecl();
  if (!MD)
    return nullptr;

  if (MD->getName() != MemberName)
    return nullptr;

  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

// Get base region for an argument expression (e.g., the device object "ca" for HL free)
const MemRegion *SAGenTestChecker::getArgBaseRegion(const CallEvent &Call, unsigned Idx,
                                                    CheckerContext &C) const {
  if (Idx >= Call.getNumArgs())
    return nullptr;

  const Expr *AE = Call.getArgExpr(Idx);
  if (!AE)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(AE, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

// Report a double free
void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, "Double free of buckets_nouse", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Handle high-level free: bch2_dev_buckets_free(ca)
  if (isBucketsHLFree(Call, C)) {
    const MemRegion *Base = getArgBaseRegion(Call, 0, C);
    if (!Base)
      return;

    // If manual free was already done on this base, it's a double free
    if (State->contains<ManualFreedBucketsNouse>(Base)) {
      reportDoubleFree(Call, C);
      return;
    }

    // Remember that the HL free has been performed for this base
    State = State->add<HighLevelFreedBucketsNouse>(Base);
    C.addTransition(State);
    return;
  }

  // Handle manual free: kfree(ca->buckets_nouse)
  if (isKfree(Call, C)) {
    if (Call.getNumArgs() == 0)
      return;

    const Expr *ArgE = Call.getArgExpr(0);
    const MemRegion *Base = getOwnerRegionIfMember(ArgE, "buckets_nouse", C);
    if (!Base)
      return; // Not freeing the specific member we care about

    // If HL free already happened, this is a double free
    if (State->contains<HighLevelFreedBucketsNouse>(Base)) {
      reportDoubleFree(Call, C);
      return;
    }

    // Record manual free of the member
    State = State->add<ManualFreedBucketsNouse>(Base);
    C.addTransition(State);
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of ca->buckets_nouse when both kfree(member) and bch2_dev_buckets_free(ca) are called",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
