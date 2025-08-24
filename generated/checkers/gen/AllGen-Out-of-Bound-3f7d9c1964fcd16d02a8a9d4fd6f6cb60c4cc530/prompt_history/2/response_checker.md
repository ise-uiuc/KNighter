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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedLenSet, const MemRegion*)

namespace {
class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Unvalidated device length", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

   private:

      bool isInVirtnetProbe(CheckerContext &C) const;
      const BinaryOperator *getEnclosingAssignment(const Expr *E, CheckerContext &C) const;
      const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;
      void reportUnvalidatedUse(const CallEvent &Call, CheckerContext &C, const Expr *ArgE = nullptr) const;
      bool isVirtioCread8Call(const CallEvent &Call, CheckerContext &C) const;
      bool isVirtnetInitDefaultRss(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::isInVirtnetProbe(CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx) return false;
  const Decl *D = LCtx->getDecl();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD) return false;
  return FD->getNameAsString() == "virtnet_probe";
}

const BinaryOperator *SAGenTestChecker::getEnclosingAssignment(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(E, C);
  if (BO && BO->isAssignmentOp())
    return BO;
  return nullptr;
}

const MemRegion *SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

bool SAGenTestChecker::isVirtioCread8Call(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "virtio_cread8", C);
}

bool SAGenTestChecker::isVirtnetInitDefaultRss(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "virtnet_init_default_rss", C);
}

void SAGenTestChecker::reportUnvalidatedUse(const CallEvent &Call, CheckerContext &C, const Expr *ArgE) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "rss_key_size used without validating against VIRTIO_NET_RSS_MAX_KEY_SIZE", N);
  if (ArgE)
    R->addRange(ArgE->getSourceRange());
  else
    R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Only care within virtnet_probe to keep noise low and match the target bug.
  if (!isInVirtnetProbe(C))
    return;

  if (!isVirtioCread8Call(Call, C))
    return;

  // Ensure the offset argument mentions rss_max_key_size.
  if (Call.getNumArgs() < 2)
    return;
  const Expr *OffArg = Call.getArgExpr(1);
  if (!OffArg)
    return;

  if (!ExprHasName(OffArg, "rss_max_key_size", C))
    return;

  // Find the assignment receiving the virtio_cread8 result.
  const Expr *Origin = Call.getOriginExpr();
  const BinaryOperator *AssignBO = getEnclosingAssignment(Origin, C);
  if (!AssignBO)
    return;

  const Expr *LHS = AssignBO->getLHS();
  if (!LHS)
    return;

  // Heuristic: ensure LHS name contains rss_key_size to match the exact field.
  if (!ExprHasName(LHS, "rss_key_size", C))
    return;

  const MemRegion *LHSRegBase = getBaseRegionFromExpr(LHS, C);
  if (!LHSRegBase)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<UncheckedLenSet>(LHSRegBase)) {
    State = State->add<UncheckedLenSet>(LHSRegBase);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!isInVirtnetProbe(C))
    return;

  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  const BinaryOperator *BO = nullptr;

  if (CondE) {
    if (const auto *TryBO = dyn_cast<BinaryOperator>(CondE->IgnoreParenImpCasts()))
      BO = TryBO;
  }
  if (!BO) {
    // Try to find a binary operator within the condition tree.
    BO = findSpecificTypeInChildren<BinaryOperator>(Condition);
  }
  if (!BO)
    return;

  BinaryOperatorKind Op = BO->getOpcode();
  switch (Op) {
    case BO_LT: case BO_LE: case BO_GT: case BO_GE: case BO_EQ: case BO_NE:
      break;
    default:
      return; // Not a comparison
  }

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  bool LHSHasMax = ExprHasName(LHS, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C);
  bool RHSHasMax = ExprHasName(RHS, "VIRTIO_NET_RSS_MAX_KEY_SIZE", C);
  if (!LHSHasMax && !RHSHasMax)
    return;

  const Expr *LenExpr = LHSHasMax ? RHS : LHS;

  // We also accept textual presence of rss_key_size in the comparison as a strong hint.
  if (!ExprHasName(LenExpr, "rss_key_size", C))
    return;

  const MemRegion *LenRegBase = getBaseRegionFromExpr(LenExpr, C);
  if (!LenRegBase)
    return;

  if (State->contains<UncheckedLenSet>(LenRegBase)) {
    State = State->remove<UncheckedLenSet>(LenRegBase);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isInVirtnetProbe(C))
    return;

  ProgramStateRef State = C.getState();

  // 1) General case: any call argument expression that mentions rss_key_size
  // and maps to an unvalidated region should be reported.
  for (unsigned i = 0, e = Call.getNumArgs(); i != e; ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    // Only consider arguments that refer to rss_key_size to avoid false positives.
    if (!ExprHasName(ArgE, "rss_key_size", C))
      continue;

    const MemRegion *ArgBase = getBaseRegionFromExpr(ArgE, C);
    if (!ArgBase)
      continue;

    if (State->contains<UncheckedLenSet>(ArgBase)) {
      reportUnvalidatedUse(Call, C, ArgE);
      // Don't return; keep looking for multiple uses in the same call if any.
    }
  }

  // 2) Specific sink: virtnet_init_default_rss(vi)
  // This function will set default RSS using rss_key_size; if the 'vi'
  // region is still unvalidated, warn here even if rss_key_size isn't passed
  // explicitly as an argument.
  if (isVirtnetInitDefaultRss(Call, C) && Call.getNumArgs() >= 1) {
    const Expr *ViArg = Call.getArgExpr(0);
    if (ViArg) {
      const MemRegion *ViBase = getBaseRegionFromExpr(ViArg, C);
      if (ViBase && State->contains<UncheckedLenSet>(ViBase)) {
        reportUnvalidatedUse(Call, C, ViArg);
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect unvalidated rss_key_size against VIRTIO_NET_RSS_MAX_KEY_SIZE before use",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
