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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/ImmutableSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: fields that were released but not set to NULL.
REGISTER_SET_WITH_PROGRAMSTATE(ReleasedFields, const FieldRegion *)
// Program state: where the release happened (to anchor diagnostics).
REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedOrigin, const FieldRegion *, const Stmt *)

namespace {

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::Bind,
      check::EndFunction
    > {

   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Released field not set to NULL", "Resource Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helpers to identify calls
  static bool callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C);
  static bool isDirectFileRelease(const CallEvent &Call, CheckerContext &C); // fput
  static bool isBtrfsCloseBdev(const CallEvent &Call, CheckerContext &C);    // btrfs_close_bdev

  // Helpers to extract FieldRegion targets
  const FieldRegion *getFieldRegionFromMemberExpr(const MemberExpr *ME,
                                                  CheckerContext &C) const;

  const FieldRegion *getFieldRegionForNamedFieldOfBaseExpr(const Expr *Base,
                                                           StringRef FieldName,
                                                           CheckerContext &C) const;

  const FieldDecl *findFieldDeclByNameInType(QualType QT, StringRef FieldName) const;

  const MemRegion *getPointeeRegionFromBaseExpr(const Expr *Base, CheckerContext &C) const;

  // Null check helper
  static bool isNullSVal(SVal V);

  // Reporting helpers
  void reportDoubleRelease(const FieldRegion *FR, const CallEvent &Call,
                           CheckerContext &C) const;

  void reportNotNulledAtEnd(const FieldRegion *FR, CheckerContext &C) const;
};

// ---- Helper implementations ----

bool SAGenTestChecker::callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (E && ExprHasName(E, Name, C))
    return true;
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  return false;
}

bool SAGenTestChecker::isDirectFileRelease(const CallEvent &Call, CheckerContext &C) {
  return callHasName(Call, "fput", C);
}

bool SAGenTestChecker::isBtrfsCloseBdev(const CallEvent &Call, CheckerContext &C) {
  return callHasName(Call, "btrfs_close_bdev", C);
}

const FieldDecl *SAGenTestChecker::findFieldDeclByNameInType(QualType QT, StringRef FieldName) const {
  if (QT.isNull())
    return nullptr;

  if (const RecordType *RT = QT->getAs<RecordType>()) {
    const RecordDecl *RD = RT->getDecl();
    if (!RD)
      return nullptr;
    for (const FieldDecl *FD : RD->fields()) {
      if (FD && FD->getName() == FieldName)
        return FD;
    }
  }
  return nullptr;
}

const MemRegion *SAGenTestChecker::getPointeeRegionFromBaseExpr(const Expr *Base, CheckerContext &C) const {
  if (!Base)
    return nullptr;
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(Base, C.getLocationContext());
  if (auto L = SV.getAs<loc::MemRegionVal>()) {
    const MemRegion *Reg = L->getRegion();
    if (Reg) {
      Reg = Reg->getBaseRegion();
      return Reg;
    }
  }
  return nullptr;
}

const FieldRegion *SAGenTestChecker::getFieldRegionFromMemberExpr(const MemberExpr *ME,
                                                                  CheckerContext &C) const {
  if (!ME)
    return nullptr;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return nullptr;

  const Expr *Base = ME->getBase();
  if (!Base)
    return nullptr;

  const MemRegion *Super = nullptr;

  // For "->", Base is a pointer; for ".", Base is an lvalue of the object.
  if (ME->isArrow() || Base->getType()->isPointerType()) {
    Super = getPointeeRegionFromBaseExpr(Base, C);
  } else {
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(Base, C.getLocationContext());
    if (auto L = SV.getAs<loc::MemRegionVal>()) {
      Super = L->getRegion();
      if (Super)
        Super = Super->getBaseRegion();
    }
  }
  if (!Super)
    return nullptr;

  const SubRegion *SR = dyn_cast<SubRegion>(Super);
  if (!SR)
    return nullptr;

  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const FieldRegion *FR = dyn_cast<FieldRegion>(MRMgr.getFieldRegion(FD, SR));
  return FR;
}

const FieldRegion *SAGenTestChecker::getFieldRegionForNamedFieldOfBaseExpr(const Expr *Base,
                                                                           StringRef FieldName,
                                                                           CheckerContext &C) const {
  if (!Base)
    return nullptr;

  // Obtain pointee type of Base.
  QualType Ty = Base->getType();
  QualType PointeeTy = Ty->isPointerType() ? Ty->getPointeeType() : Ty;

  const FieldDecl *FD = findFieldDeclByNameInType(PointeeTy, FieldName);
  if (!FD)
    return nullptr;

  const MemRegion *Super = nullptr;
  if (Ty->isPointerType()) {
    Super = getPointeeRegionFromBaseExpr(Base, C);
  } else {
    ProgramStateRef State = C.getState();
    SVal SV = State->getSVal(Base, C.getLocationContext());
    if (auto L = SV.getAs<loc::MemRegionVal>()) {
      Super = L->getRegion();
      if (Super)
        Super = Super->getBaseRegion();
    }
  }
  if (!Super)
    return nullptr;

  const SubRegion *SR = dyn_cast<SubRegion>(Super);
  if (!SR)
    return nullptr;

  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const FieldRegion *FR = dyn_cast<FieldRegion>(MRMgr.getFieldRegion(FD, SR));
  return FR;
}

bool SAGenTestChecker::isNullSVal(SVal V) {
  if (auto LC = V.getAs<loc::ConcreteInt>())
    return LC->getValue().isZero();
  if (auto NC = V.getAs<nonloc::ConcreteInt>())
    return NC->getValue().isZero();
  return false;
}

// ---- Reporting ----

void SAGenTestChecker::reportDoubleRelease(const FieldRegion *FR, const CallEvent &Call,
                                           CheckerContext &C) const {
  if (!FR)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  StringRef FieldName = FR->getDecl()->getName();
  SmallString<128> Msg;
  Msg += "Double release of field '";
  Msg += FieldName;
  Msg += "'";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());

  // Point to the original release if we know it.
  ProgramStateRef State = C.getState();
  if (const Stmt *const *Orig = State->get<ReleasedOrigin>(FR)) {
    PathDiagnosticLocation PL = PathDiagnosticLocation::createBegin(*Orig, C.getSourceManager(), C.getLocationContext());
    R->addNote("Field was released here", PL);
  }

  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportNotNulledAtEnd(const FieldRegion *FR, CheckerContext &C) const {
  if (!FR)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  StringRef FieldName = FR->getDecl()->getName();
  SmallString<160> Msg;
  Msg += "Field '";
  Msg += FieldName;
  Msg += "' released but not set to NULL";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);

  ProgramStateRef State = C.getState();
  if (const Stmt *const *Orig = State->get<ReleasedOrigin>(FR)) {
    PathDiagnosticLocation PL = PathDiagnosticLocation::createBegin(*Orig, C.getSourceManager(), C.getLocationContext());
    R->addNote("Field was released here", PL);
  }

  C.emitReport(std::move(R));
}

// ---- Callbacks ----

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Case 1: Direct release via fput(device->bdev_file)
  if (isDirectFileRelease(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      const Expr *ArgE = Call.getArgExpr(0);
      if (ArgE) {
        // Try to find a MemberExpr within the argument (handles casts/macros).
        const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(ArgE);
        if (ME) {
          const FieldRegion *FR = getFieldRegionFromMemberExpr(ME, C);
          if (FR) {
            State = State->add<ReleasedFields>(FR);
            if (const Stmt *S = Call.getOriginExpr())
              State = State->set<ReleasedOrigin>(FR, S);
            C.addTransition(State);
          }
        }
      }
    }
    return;
  }

  // Case 2: Container release btrfs_close_bdev(device) which releases device->bdev_file
  if (isBtrfsCloseBdev(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      const Expr *Base = Call.getArgExpr(0);
      const FieldRegion *FR = getFieldRegionForNamedFieldOfBaseExpr(Base, "bdev_file", C);
      if (FR) {
        State = State->add<ReleasedFields>(FR);
        if (const Stmt *S = Call.getOriginExpr())
          State = State->set<ReleasedOrigin>(FR, S);
        C.addTransition(State);
      }
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect immediate double release attempts.

  // fput(device->bdev_file) while device->bdev_file is already released
  if (isDirectFileRelease(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      const Expr *ArgE = Call.getArgExpr(0);
      const MemberExpr *ME = ArgE ? findSpecificTypeInChildren<MemberExpr>(ArgE) : nullptr;
      if (ME) {
        const FieldRegion *FR = getFieldRegionFromMemberExpr(ME, C);
        if (FR && State->contains<ReleasedFields>(FR)) {
          reportDoubleRelease(FR, Call, C);
        }
      }
    }
    return;
  }

  // btrfs_close_bdev(device) again while device->bdev_file is already released
  if (isBtrfsCloseBdev(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      const Expr *Base = Call.getArgExpr(0);
      const FieldRegion *FR = getFieldRegionForNamedFieldOfBaseExpr(Base, "bdev_file", C);
      if (FR && State->contains<ReleasedFields>(FR)) {
        reportDoubleRelease(FR, Call, C);
      }
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  // We are interested in direct assignments to a field region, like: device->bdev_file = NULL;
  const FieldRegion *FR = dyn_cast<FieldRegion>(R);
  if (!FR)
    return;

  if (State->contains<ReleasedFields>(FR) && isNullSVal(Val)) {
    // The released field is now nulled out: clear tracking.
    State = State->remove<ReleasedFields>(FR);
    State = State->remove<ReleasedOrigin>(FR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  auto Set = State->get<ReleasedFields>();
  if (Set.isEmpty())
    return;

  // Report each field that was released but not set to NULL before returning.
  for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
    const FieldRegion *FR = *I;
    // Focus on the targeted pattern; report for any field, including 'bdev_file'.
    reportNotNulledAtEnd(FR, C);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects released struct fields not nulled and double release via stale non-NULL checks (e.g., bdev_file)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
