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
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: map object-region -> Stmt* of the publish call
REGISTER_MAP_WITH_PROGRAMSTATE(PublishedObjMap, const MemRegion*, const Stmt*)
// Program state: simple pointer aliasing (pointer var region -> canonical object region)
REGISTER_MAP_WITH_PROGRAMSTATE(AliasMap, const MemRegion*, const MemRegion*)
// Program state: already-reported objects (per-path)
REGISTER_SET_WITH_PROGRAMSTATE(AlreadyReportedSet, const MemRegion*)

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostCall,
        check::PreCall,
        check::Bind> {

   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(new BugType(this,
                     "Object modified after publishing to ID registry",
                     "UAF risk")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  bool isIoctlOrCreateFunction(CheckerContext &C) const;
  const MemRegion *getBaseObjectRegion(const MemRegion *R) const;
  const MemRegion *getRootAlias(const MemRegion *R, ProgramStateRef State) const;

  bool isPublishCall(const CallEvent &Call, unsigned &EntryParamIndex,
                     CheckerContext &C) const;

  bool isGetRefLikeCall(const Expr *E, CheckerContext &C) const;

  void reportAfterPublish(const MemRegion *Base, const Stmt *WriteStmt,
                          CheckerContext &C) const;
};

// Return true if current function name contains "ioctl" or "create".
bool SAGenTestChecker::isIoctlOrCreateFunction(CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  const Decl *D = LCtx ? LCtx->getDecl() : nullptr;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;

  StringRef Name = FD->getName();
  return (Name.contains("ioctl") || Name.contains("create"));
}

const MemRegion *SAGenTestChecker::getBaseObjectRegion(const MemRegion *R) const {
  if (!R) return nullptr;
  return R->getBaseRegion();
}

const MemRegion *SAGenTestChecker::getRootAlias(const MemRegion *R, ProgramStateRef State) const {
  if (!R) return nullptr;
  const MemRegion *Cur = R;
  // Follow alias map transitively to a fixed point.
  while (true) {
    const MemRegion *Next = nullptr;
    if (const MemRegion *const *PNext = State->get<AliasMap>(Cur))
      Next = *PNext;
    if (!Next || Next == Cur)
      break;
    Cur = Next;
  }
  return Cur;
}

// Detect publish calls and provide the object-entry argument index.
bool SAGenTestChecker::isPublishCall(const CallEvent &Call, unsigned &EntryParamIndex,
                                     CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Prefer ExprHasName to match callee reliably.
  if (ExprHasName(Origin, "xa_alloc_cyclic", C)) {
    EntryParamIndex = 2; // xarray, id, entry, start, max, gfp, flags
    return true;
  }
  if (ExprHasName(Origin, "xa_alloc", C)) {
    EntryParamIndex = 2; // xarray, id, entry, ...
    return true;
  }
  if (ExprHasName(Origin, "idr_alloc_u32", C)) {
    EntryParamIndex = 1; // idr, entry, id, ...
    return true;
  }
  if (ExprHasName(Origin, "idr_alloc", C)) {
    EntryParamIndex = 1; // idr, entry, start, end, gfp
    return true;
  }

  // Fallback to exact callee identifier match if OriginExpr matching didn't trigger.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef N = ID->getName();
    if (N.equals("xa_alloc_cyclic")) { EntryParamIndex = 2; return true; }
    if (N.equals("xa_alloc"))        { EntryParamIndex = 2; return true; }
    if (N.equals("idr_alloc_u32"))   { EntryParamIndex = 1; return true; }
    if (N.equals("idr_alloc"))       { EntryParamIndex = 1; return true; }
  }

  return false;
}

bool SAGenTestChecker::isGetRefLikeCall(const Expr *E, CheckerContext &C) const {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    // Heuristic: function name contains "get"
    return ExprHasName(CE, "get", C);
  }
  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isIoctlOrCreateFunction(C))
    return;

  ProgramStateRef State = C.getState();

  unsigned EntryIdx = 0;
  if (!isPublishCall(Call, EntryIdx, C))
    return;

  if (EntryIdx >= Call.getNumArgs())
    return;

  // Extract the object being published (entry parameter).
  SVal EntrySV = Call.getArgSVal(EntryIdx);
  const MemRegion *ObjReg = EntrySV.getAsRegion();
  if (!ObjReg)
    return;
  ObjReg = getBaseObjectRegion(ObjReg);
  if (!ObjReg)
    return;

  // Canonicalize via alias map (if any).
  ObjReg = getRootAlias(ObjReg, State);
  if (!ObjReg)
    return;

  // Save the origin statement of the publish call for diagnostics.
  const Stmt *PublishStmt = Call.getOriginExpr();
  if (!PublishStmt)
    return;

  // Record that this object has been published to a user-visible ID registry.
  State = State->set<PublishedObjMap>(ObjReg, PublishStmt);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isIoctlOrCreateFunction(C))
    return;

  ProgramStateRef State = C.getState();

  // Optional conservative handling: if a known function dereferences a parameter,
  // and that parameter corresponds to an already-published object, warn.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    SVal Arg = Call.getArgSVal(Idx);
    const MemRegion *MR = Arg.getAsRegion();
    if (!MR)
      continue;

    MR = getBaseObjectRegion(MR);
    if (!MR)
      continue;

    MR = getRootAlias(MR, State);
    if (!MR)
      continue;

    const Stmt *PubStmt = nullptr;
    if (const Stmt *const *PPub = State->get<PublishedObjMap>(MR))
      PubStmt = *PPub;
    if (!PubStmt)
      continue;

    if (State->contains<AlreadyReportedSet>(MR))
      continue;

    // Report: object potentially accessed after publish.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Object may be accessed after publishing via xa/id alloc; publish must be last to prevent UAF.",
        N);
    R->addRange(Call.getSourceRange());
    // Highlight publish call as well if available.
    R->addRange(PubStmt->getSourceRange());

    C.emitReport(std::move(R));

    // Avoid duplicate reports on this path for the same object.
    State = State->add<AlreadyReportedSet>(MR);
    C.addTransition(State);
    return; // One report is enough here.
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!isIoctlOrCreateFunction(C))
    return;

  ProgramStateRef State = C.getState();

  // 1) Alias tracking: pointer variable assignment like "p2 = p1;"
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    const MemRegion *LHSBase = LHSReg->getBaseRegion();
    // Only consider simple variable regions for aliasing
    if (isa<VarRegion>(LHSBase)) {
      if (const MemRegion *RHSReg = Val.getAsRegion()) {
        RHSReg = getBaseObjectRegion(RHSReg);
        if (RHSReg) {
          RHSReg = getRootAlias(RHSReg, State);
          if (RHSReg) {
            State = State->set<AliasMap>(LHSBase, RHSReg);
            C.addTransition(State);
          }
          }
        }
      }
    }
  }

  // 2) Detect writes to a published object's fields after publish.
  const MemRegion *Target = Loc.getAsRegion();
  if (!Target)
    return;

  const MemRegion *BaseObj = getBaseObjectRegion(Target);
  if (!BaseObj)
    return;

  BaseObj = getRootAlias(BaseObj, State);
  if (!BaseObj)
    return;

  const Stmt *PubStmt = nullptr;
  if (const Stmt *const *PPub = State->get<PublishedObjMap>(BaseObj))
    PubStmt = *PPub;
  if (!PubStmt)
    return;

  if (State->contains<AlreadyReportedSet>(BaseObj))
    return;

  // We are about to modify a region under the published object.
  // Specialize message if RHS looks like a "*get*" call (ref acquire).
  bool IsRefAcquire = false;
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      IsRefAcquire = isGetRefLikeCall(BO->getRHS(), C);
    }
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg;
  if (IsRefAcquire) {
    Msg = "Reference taken after publishing; publish must be last to prevent UAF race.";
  } else {
    Msg = "Object modified after publishing via xa/id alloc; publish must be last to prevent UAF.";
  }

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  R->addRange(PubStmt->getSourceRange());
  C.emitReport(std::move(R));

  State = State->add<AlreadyReportedSet>(BaseObj);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing objects to ID registries (xa/id) before final initialization/ref acquisition, which can cause UAF races",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
