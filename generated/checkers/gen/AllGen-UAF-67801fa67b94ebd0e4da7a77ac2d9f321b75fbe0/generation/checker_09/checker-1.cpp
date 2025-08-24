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
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Lex/Lexer.h"
#include <string>
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

// Map a published object's base MemRegion to the Stmt where it was published
REGISTER_MAP_WITH_PROGRAMSTATE(PublishedObjMap, const MemRegion*, const Stmt*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::Bind
  > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Publish-before-init leads to UAF", "Concurrency/Ordering")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:
      // Helpers
      bool isPublishCall(const CallEvent &Call, unsigned &ObjIdx, CheckerContext &C) const;
      const MemRegion *getPublishedObjRegion(const CallEvent &Call, unsigned ObjIdx, CheckerContext &C) const;
      bool looksSuspiciousFieldWrite(const Expr *LHS, CheckerContext &C) const;
      void reportPublishBeforeInit(const MemRegion *ObjReg, const Stmt *StoreS, const Stmt *PublishS, CheckerContext &C) const;
};

// Return true if Call is xa_alloc/xa_alloc_cyclic/idr_alloc/idr_alloc_cyclic.
// Sets ObjIdx to the argument index of the published object.
bool SAGenTestChecker::isPublishCall(const CallEvent &Call, unsigned &ObjIdx, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // xa_alloc(..., obj, ...)
  if (ExprHasName(Origin, "xa_alloc", C)) {
    // xa_alloc(xa, idp, entry, ...)
    ObjIdx = 2;
    return true;
  }
  if (ExprHasName(Origin, "xa_alloc_cyclic", C)) {
    // xa_alloc_cyclic(xa, idp, entry, ...)
    ObjIdx = 2;
    return true;
  }
  // idr_alloc(..., obj, ...)
  if (ExprHasName(Origin, "idr_alloc", C)) {
    // idr_alloc(idr, ptr, ...)
    ObjIdx = 1;
    return true;
  }
  if (ExprHasName(Origin, "idr_alloc_cyclic", C)) {
    // idr_alloc_cyclic(idr, ptr, ...)
    ObjIdx = 1;
    return true;
  }

  return false;
}

const MemRegion *SAGenTestChecker::getPublishedObjRegion(const CallEvent &Call, unsigned ObjIdx, CheckerContext &C) const {
  if (ObjIdx >= Call.getNumArgs())
    return nullptr;

  const Expr *ArgE = Call.getArgExpr(ObjIdx);
  if (!ArgE)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
  if (!MR)
    return nullptr;

  MR = MR->getBaseRegion();
  return MR;
}

bool SAGenTestChecker::looksSuspiciousFieldWrite(const Expr *LHS, CheckerContext &C) const {
  if (!LHS)
    return false;

  static const char *SuspiciousNames[] = {
      "ref", "kref", "refs", "owner", "file", "xef", "ops", "state", "id", "list", "node"
  };

  const Expr *E = LHS->IgnoreParenCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const ValueDecl *VD = ME->getMemberDecl()) {
      StringRef Name = VD->getName();
      for (const char *Sub : SuspiciousNames) {
        if (Name.contains(Sub))
          return true;
      }
    }
    // Fallback to textual search if needed
    for (const char *Sub : SuspiciousNames) {
      if (ExprHasName(LHS, Sub, C))
        return true;
    }
    return false;
  }

  // Array subscripts or other lvalues - use textual fallback
  for (const char *Sub : SuspiciousNames) {
    if (ExprHasName(LHS, Sub, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  unsigned ObjIdx = 0;
  if (!isPublishCall(Call, ObjIdx, C))
    return;

  const MemRegion *ObjReg = getPublishedObjRegion(Call, ObjIdx, C);
  if (!ObjReg)
    return;

  // Remember that this object was published here.
  const Stmt *Where = Call.getOriginExpr();
  State = State->set<PublishedObjMap>(ObjReg, Where);
  C.addTransition(State);
}

void SAGenTestChecker::reportPublishBeforeInit(const MemRegion *ObjReg,
                                               const Stmt *StoreS,
                                               const Stmt *PublishS,
                                               CheckerContext &C) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Published object via xa_alloc/idr_alloc before completing initialization", N);

  if (StoreS)
    R->addRange(StoreS->getSourceRange());

  if (PublishS) {
    PathDiagnosticLocation PubLoc =
        PathDiagnosticLocation::createBegin(PublishS, C.getSourceManager(),
                                            C.getLocationContext());
    R->addNote("Object is published here", PubLoc);
  }

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LReg = Loc.getAsRegion();
  if (!LReg)
    return;

  // We are only interested in stores to fields/elements of a published object.
  const MemRegion *BaseReg = LReg->getBaseRegion();
  if (!BaseReg)
    return;

  // get<PublishedObjMap>(Key) returns a pointer to the mapped value (or null).
  const Stmt *const *PublishSitePtr = State->get<PublishedObjMap>(BaseReg);
  if (!PublishSitePtr)
    return;
  const Stmt *PublishSite = *PublishSitePtr;

  // Try to get LHS expression for field-name heuristics.
  const Expr *LHS = nullptr;
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      LHS = BO->getLHS();
  } else if (const auto *UO = dyn_cast_or_null<UnaryOperator>(S)) {
    // e.g., ++obj->ref or similar - treat as a write
    if (UO->isIncrementDecrementOp())
      LHS = UO->getSubExpr();
  }

  // If we have an LHS, apply suspicious field-name filter to reduce FPs.
  if (LHS && !looksSuspiciousFieldWrite(LHS, C))
    return;

  // Report and optionally silence further reports for this object by removing it.
  reportPublishBeforeInit(BaseReg, S, PublishSite, C);
  State = State->remove<PublishedObjMap>(BaseReg);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing an object via xa_alloc/idr_alloc before completing initialization (may cause UAF)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
