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
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: map published object region -> publication site (Stmt*)
REGISTER_MAP_WITH_PROGRAMSTATE(PublishedMap, const MemRegion*, const Stmt*)
// Program state: set of regions already reported (to avoid duplicates)
REGISTER_SET_WITH_PROGRAMSTATE(ReportedSet, const MemRegion*)

namespace {
class SAGenTestChecker : public Checker<
    check::PostCall,
    check::Bind,
    check::PreCall
  > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Early ID publish (potential UAF race)", "Concurrency")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      bool inIoctlFunction(CheckerContext &C) const;
      bool isPublicationCall(const CallEvent &Call, unsigned &PtrArgIndex, CheckerContext &C) const;
      const MemRegion *getPublishedObjectRegionFromCall(const CallEvent &Call, unsigned PtrArgIndex, CheckerContext &C) const;

      bool isPostPublishMutatingCall(const CallEvent &Call, unsigned &DestPtrIndex, CheckerContext &C) const;

      void reportEarlyPublish(const MemRegion *Base, const Stmt *ModStmt,
                              const Stmt *PubStmt, CheckerContext &C) const;
};

bool SAGenTestChecker::inIoctlFunction(CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  if (!LC) return false;
  const Decl *D = LC->getDecl();
  if (!D) return false;

  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return false;

  // Heuristic: only act in functions whose names contain "ioctl"
  StringRef Name = FD->getName();
  return Name.contains_insensitive("ioctl");
}

// Identify publication calls and return the index of the pointer argument
bool SAGenTestChecker::isPublicationCall(const CallEvent &Call, unsigned &PtrArgIndex, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // xa_* APIs publish at arg index 2
  if (ExprHasName(Origin, "xa_alloc", C) ||
      ExprHasName(Origin, "xa_insert", C) ||
      ExprHasName(Origin, "xa_store", C)) {
    PtrArgIndex = 2;
    return Call.getNumArgs() > PtrArgIndex;
  }

  // idr_* APIs publish at arg index 1
  if (ExprHasName(Origin, "idr_alloc", C) ||
      ExprHasName(Origin, "idr_alloc_cyclic", C)) {
    PtrArgIndex = 1;
    return Call.getNumArgs() > PtrArgIndex;
  }

  return false;
}

// Extract the base MemRegion for the object being published (pointed-to region)
const MemRegion *SAGenTestChecker::getPublishedObjectRegionFromCall(const CallEvent &Call, unsigned PtrArgIndex, CheckerContext &C) const {
  if (PtrArgIndex >= Call.getNumArgs())
    return nullptr;

  // Prefer SVal-based extraction
  SVal ArgV = Call.getArgSVal(PtrArgIndex);
  if (const MemRegion *MR = ArgV.getAsRegion()) {
    const MemRegion *Base = MR->getBaseRegion();
    return Base;
  }

  // Fallback to expression-based extraction
  if (const Expr *AE = Call.getArgExpr(PtrArgIndex)) {
    if (const MemRegion *MR = getMemRegionFromExpr(AE, C)) {
      const MemRegion *Base = MR->getBaseRegion();
      return Base;
    }
  }
  return nullptr;
}

// Identify common memory-mutating functions (dest pointer index)
bool SAGenTestChecker::isPostPublishMutatingCall(const CallEvent &Call, unsigned &DestPtrIndex, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // Minimal set: memset(dest, ...), memcpy(dest, src, ...)
  if (ExprHasName(Origin, "memset", C)) {
    DestPtrIndex = 0;
    return Call.getNumArgs() > DestPtrIndex;
  }
  if (ExprHasName(Origin, "memcpy", C)) {
    DestPtrIndex = 0;
    return Call.getNumArgs() > DestPtrIndex;
  }

  return false;
}

void SAGenTestChecker::reportEarlyPublish(const MemRegion *Base,
                                          const Stmt *ModStmt,
                                          const Stmt *PubStmt,
                                          CheckerContext &C) const {
  if (!BT || !Base || !ModStmt)
    return;

  ProgramStateRef State = C.getState();
  // Mark reported to avoid duplicate reports along the same path
  ProgramStateRef NewState = State->add<ReportedSet>(Base);

  ExplodedNode *N = C.generateNonFatalErrorNode(NewState);
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Object published to ID registry before finalization; publish must be last", N);
  R->addRange(ModStmt->getSourceRange());
  if (PubStmt)
    R->addRange(PubStmt->getSourceRange());

  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!inIoctlFunction(C))
    return;

  unsigned PtrIdx = 0;
  if (!isPublicationCall(Call, PtrIdx, C))
    return;

  const MemRegion *ObjBase = getPublishedObjectRegionFromCall(Call, PtrIdx, C);
  if (!ObjBase)
    return;

  ProgramStateRef State = C.getState();
  // Record publication site
  const Stmt *PubSite = Call.getOriginExpr();
  State = State->set<PublishedMap>(ObjBase, PubSite);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  if (!inIoctlFunction(C))
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return;

  ProgramStateRef State = C.getState();

  // Has this base been published?
  const Stmt *const *PubStmtPtr = State->get<PublishedMap>(Base);
  if (!PubStmtPtr)
    return;
  const Stmt *PubStmt = *PubStmtPtr;

  // Already reported?
  if (State->contains<ReportedSet>(Base))
    return;

  // This store is a post-publication mutation, report it.
  reportEarlyPublish(Base, StoreE, PubStmt, C);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!inIoctlFunction(C))
    return;

  unsigned DestIdx = 0;
  if (!isPostPublishMutatingCall(Call, DestIdx, C))
    return;

  ProgramStateRef State = C.getState();
  SVal DestV = Call.getArgSVal(DestIdx);
  const MemRegion *DestR = DestV.getAsRegion();
  if (!DestR)
    return;

  const MemRegion *Base = DestR->getBaseRegion();
  if (!Base)
    return;

  // Has this base been published?
  const Stmt *const *PubStmtPtr = State->get<PublishedMap>(Base);
  if (!PubStmtPtr)
    return;
  const Stmt *PubStmt = *PubStmtPtr;

  // Already reported?
  if (State->contains<ReportedSet>(Base))
    return;

  // This call mutates the object after publication
  const Stmt *S = Call.getOriginExpr();
  reportEarlyPublish(Base, S, PubStmt, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing objects into ID registries before finalization (must be last in ioctl)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
