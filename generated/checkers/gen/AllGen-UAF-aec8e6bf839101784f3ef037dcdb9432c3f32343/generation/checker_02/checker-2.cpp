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
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Track resource pointers that were released and must be set to NULL.
// Key: The exact MemRegion (e.g., FieldRegion for device->bdev_file or a pointer VarRegion).
// Val: true (placeholder), existence means "released but not NULLed".
REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedFieldMap, const MemRegion *, bool)
// Track which function context released the region, so we only warn at the same function's end.
REGISTER_MAP_WITH_PROGRAMSTATE(ReleaseOwnerMap, const MemRegion *, const LocationContext *)

namespace {

struct FieldReleaseEntry {
  const char *Func;
  unsigned BaseParamIndex;
  const char *FieldName;
};

// Known wrapper(s) that release a specific field of their first arg.
static const FieldReleaseEntry KnownFieldReleases[] = {
  {"btrfs_close_bdev", 0u, "bdev_file"},
};

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind,
        check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Stale pointer after release", "Resource Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:
      // Helpers
      static bool isFputCall(const CallEvent &Call, CheckerContext &C);
      static bool isKnownFieldReleaseCall(const CallEvent &Call, CheckerContext &C, FieldReleaseEntry &Out);
      static bool isNullSVal(ProgramStateRef State, SVal V);

      void markExprReleased(const Expr *PtrExpr, CheckerContext &C) const;
      void markFieldReleased(const Expr *BaseArg, StringRef FieldName, CheckerContext &C) const;

      void reportDoublePut(const CallEvent &Call, CheckerContext &C) const;
      void reportNotNullifiedAtEnd(const MemRegion *R, CheckerContext &C) const;
};

bool SAGenTestChecker::isFputCall(const CallEvent &Call, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;
  return ExprHasName(OE, "fput", C);
}

bool SAGenTestChecker::isKnownFieldReleaseCall(const CallEvent &Call, CheckerContext &C, FieldReleaseEntry &Out) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;
  for (const auto &E : KnownFieldReleases) {
    if (ExprHasName(OE, E.Func, C)) {
      Out = E;
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isNullSVal(ProgramStateRef State, SVal V) {
  if (V.isZeroConstant())
    return true;
  if (auto L = V.getAs<Loc>()) {
    ConditionTruthVal T = State->isNull(*L);
    if (T.isConstrainedTrue())
      return true;
  }
  return false;
}

void SAGenTestChecker::markExprReleased(const Expr *PtrExpr, CheckerContext &C) const {
  if (!PtrExpr) return;
  ProgramStateRef State = C.getState();

  const MemRegion *MR = getMemRegionFromExpr(PtrExpr, C);
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;

  State = State->set<ReleasedFieldMap>(MR, true);
  State = State->set<ReleaseOwnerMap>(MR, C.getLocationContext());
  C.addTransition(State);
}

void SAGenTestChecker::markFieldReleased(const Expr *BaseArg, StringRef FieldName, CheckerContext &C) const {
  if (!BaseArg) return;
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // Get pointee region of the base argument (device)
  SVal BaseVal = State->getSVal(BaseArg, LCtx);
  const MemRegion *BaseObjReg = BaseVal.getAsRegion();
  if (!BaseObjReg)
    return;
  BaseObjReg = BaseObjReg->getBaseRegion();
  if (!BaseObjReg)
    return;

  // Get the pointee record of BaseArg
  QualType BTy = BaseArg->getType();
  if (!BTy->isPointerType())
    return;
  QualType Pointee = BTy->getPointeeType();
  const RecordType *RT = Pointee->getAs<RecordType>();
  if (!RT)
    return;
  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return;

  const FieldDecl *TargetFD = nullptr;
  for (const auto *FD : RD->fields()) {
    if (FD && FD->getIdentifier() && FD->getName() == FieldName) {
      TargetFD = FD;
      break;
    }
  }
  if (!TargetFD)
    return;

  // Build a FieldRegion for BaseObjReg->FieldName
  SValBuilder &SVB = C.getSValBuilder();
  SVal BaseSV;
  if (auto L = BaseVal.getAs<Loc>()) {
    BaseSV = *L;
  } else {
    BaseSV = loc::MemRegionVal(BaseObjReg);
  }
  SVal FieldLoc = SVB.getLValueField(TargetFD, BaseSV);
  const MemRegion *FieldReg = FieldLoc.getAsRegion();
  if (!FieldReg)
    return;
  FieldReg = FieldReg->getBaseRegion();
  if (!FieldReg)
    return;

  State = State->set<ReleasedFieldMap>(FieldReg, true);
  State = State->set<ReleaseOwnerMap>(FieldReg, C.getLocationContext());
  C.addTransition(State);
}

void SAGenTestChecker::reportDoublePut(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, "Double put on an already released pointer", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportNotNullifiedAtEnd(const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto BR = std::make_unique<PathSensitiveBugReport>(*BT, "Released pointer not set to NULL", N);
  C.emitReport(std::move(BR));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFputCall(Call, C))
    return;

  // If we're calling fput() on a region already released, report immediate double-put.
  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0) return;
  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;

  ProgramStateRef State = C.getState();
  const bool *WasReleased = State->get<ReleasedFieldMap>(MR);
  if (WasReleased && *WasReleased) {
    reportDoublePut(Call, C);
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  FieldReleaseEntry E;
  if (isFputCall(Call, C)) {
    // Mark the pointer passed to fput() as released (must be set to NULL afterwards)
    const Expr *Arg0 = Call.getArgExpr(0);
    markExprReleased(Arg0, C);
    return;
  } else if (isKnownFieldReleaseCall(Call, C, E)) {
    // Mark the known field on the base argument as released
    if (E.BaseParamIndex < Call.getNumArgs()) {
      const Expr *BaseArg = Call.getArgExpr(E.BaseParamIndex);
      markFieldReleased(BaseArg, E.FieldName, C);
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *Dst = nullptr;

  if (auto L = Loc.getAs<loc::MemRegionVal>()) {
    Dst = L->getRegion();
  } else {
    Dst = Loc.getAsRegion();
  }

  if (!Dst) return;
  Dst = Dst->getBaseRegion();
  if (!Dst) return;

  const bool *WasReleased = State->get<ReleasedFieldMap>(Dst);
  if (!WasReleased) return;

  // If it was released and now assigned NULL, clear the obligation.
  if (isNullSVal(State, Val)) {
    State = State->remove<ReleasedFieldMap>(Dst);
    State = State->remove<ReleaseOwnerMap>(Dst);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  using ReleasedFieldMapTy = ProgramStateTrait<ReleasedFieldMap>::data_type;

  ReleasedFieldMapTy Map = State->get<ReleasedFieldMap>();
  if (!Map.isEmpty()) {
    const LocationContext *CurLCtx = C.getLocationContext();
    for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
      const MemRegion *R = I->first;
      const bool *Flag = State->get<ReleasedFieldMap>(R);
      if (!Flag || !*Flag) continue;

      const LocationContext *const *OwnerPtr = State->get<ReleaseOwnerMap>(R);
      if (OwnerPtr && *OwnerPtr == CurLCtx) {
        // Released in this function and not NULLed before return: warn.
        reportNotNullifiedAtEnd(R, C);
        // Do not clear here; allow path reports for each path end.
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects stale pointers after resource release that must be set to NULL (e.g., device->bdev_file after btrfs_close_bdev/fput)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
