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

using namespace clang;
using namespace ento;
using namespace taint;

// Program state customizations
// - ReleasedFieldMap: map base MemRegion* (owning-struct pointer variable) to bitmask of released fields.
REGISTER_MAP_WITH_PROGRAMSTATE(ReleasedFieldMap, const MemRegion*, unsigned)
// - PtrAliasMap: simple alias map for struct-pointer variables to a canonical base region (root).
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

static constexpr unsigned BDEV_FILE_BIT = 1u;

struct CloseHelperEntry {
  const char *Name;
  unsigned ParamIdx;
  unsigned FieldMask;
};

static const CloseHelperEntry CloseHelpers[] = {
  {"btrfs_close_bdev", 0u, BDEV_FILE_BIT},
};

static const char *SecondUseFuncs[] = {
  "fput",
  "filp_close",
};

class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::BranchCondition,
      check::Bind
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Stale struct file* field use", "Resource Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;
      const MemRegion *canonicalizeBase(const MemRegion *R, ProgramStateRef State) const;

      bool isCloseHelper(const CallEvent &Call, unsigned &ParamIdx, unsigned &FieldMask, CheckerContext &C) const;
      bool isSecondUseFunction(const CallEvent &Call, CheckerContext &C) const;

      bool getFieldAccessInfo(const Expr *E, CheckerContext &C,
                              const MemRegion *&BaseR, unsigned &FieldBit) const;

      ProgramStateRef setFieldReleased(ProgramStateRef State, const MemRegion *BaseR, unsigned FieldBit) const;
      ProgramStateRef clearFieldReleased(ProgramStateRef State, const MemRegion *BaseR, unsigned FieldBit) const;

      void reportAtCondition(const Stmt *S, CheckerContext &C, StringRef Msg) const;
      void reportAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;

      bool isStructPointerVarRegion(const MemRegion *R, CheckerContext &C) const;
};

const MemRegion *SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  return MR;
}

const MemRegion *SAGenTestChecker::canonicalizeBase(const MemRegion *R, ProgramStateRef State) const {
  if (!R) return nullptr;
  // Follow alias chain to the root.
  const MemRegion *Cur = R;
  unsigned Steps = 0;
  while (Cur) {
    const MemRegion *Next = State->get<PtrAliasMap>(Cur);
    if (!Next || Next == Cur)
      break;
    Cur = Next;
    // Protective bound to avoid infinite loops due to cycles.
    if (++Steps > 16)
      break;
  }
  return Cur ? Cur->getBaseRegion() : nullptr;
}

bool SAGenTestChecker::isCloseHelper(const CallEvent &Call, unsigned &ParamIdx, unsigned &FieldMask, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  for (const auto &Entry : CloseHelpers) {
    if (ExprHasName(Origin, Entry.Name, C)) {
      ParamIdx = Entry.ParamIdx;
      FieldMask = Entry.FieldMask;
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSecondUseFunction(const CallEvent &Call, CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  for (const char *Name : SecondUseFuncs) {
    if (ExprHasName(Origin, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::getFieldAccessInfo(const Expr *E, CheckerContext &C,
                                          const MemRegion *&BaseR, unsigned &FieldBit) const {
  BaseR = nullptr;
  FieldBit = 0;

  if (!E)
    return false;

  // We want to find a MemberExpr referencing a field like device->bdev_file.
  const MemberExpr *ME = nullptr;
  if ((ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts())) == nullptr) {
    ME = findSpecificTypeInChildren<MemberExpr>(E);
    if (!ME)
      return false;
  }

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD)
    return false;

  StringRef FieldName = VD->getName();
  if (FieldName == "bdev_file")
    FieldBit = BDEV_FILE_BIT;

  const Expr *BaseExpr = ME->getBase();
  if (!BaseExpr)
    return false;

  const MemRegion *Base = getBaseRegionFromExpr(BaseExpr, C);
  if (!Base)
    return false;

  ProgramStateRef State = C.getState();
  BaseR = canonicalizeBase(Base, State);

  return (FieldBit != 0) && (BaseR != nullptr);
}

ProgramStateRef SAGenTestChecker::setFieldReleased(ProgramStateRef State, const MemRegion *BaseR, unsigned FieldBit) const {
  if (!BaseR || FieldBit == 0)
    return State;
  unsigned Cur = 0;
  if (const unsigned *P = State->get<ReleasedFieldMap>(BaseR))
    Cur = *P;
  Cur |= FieldBit;
  State = State->set<ReleasedFieldMap>(BaseR, Cur);
  return State;
}

ProgramStateRef SAGenTestChecker::clearFieldReleased(ProgramStateRef State, const MemRegion *BaseR, unsigned FieldBit) const {
  if (!BaseR || FieldBit == 0)
    return State;
  unsigned Cur = 0;
  if (const unsigned *P = State->get<ReleasedFieldMap>(BaseR))
    Cur = *P;

  Cur &= ~FieldBit;
  if (Cur == 0) {
    State = State->remove<ReleasedFieldMap>(BaseR);
  } else {
    State = State->set<ReleasedFieldMap>(BaseR, Cur);
  }
  return State;
}

void SAGenTestChecker::reportAtCondition(const Stmt *S, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

bool SAGenTestChecker::isStructPointerVarRegion(const MemRegion *R, CheckerContext &C) const {
  if (!R)
    return false;
  const VarRegion *VR = dyn_cast<VarRegion>(R->getBaseRegion());
  if (!VR)
    return false;
  QualType T = VR->getValueType();
  if (T.isNull())
    return false;
  if (!T->isPointerType())
    return false;
  QualType Pointee = T->getPointeeType();
  if (Pointee.isNull())
    return false;
  return Pointee->isRecordType();
}

// Callback implementations

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned ParamIdx = 0, FieldMask = 0;
  if (!isCloseHelper(Call, ParamIdx, FieldMask, C))
    return;

  if (ParamIdx >= Call.getNumArgs())
    return;

  const Expr *ArgE = Call.getArgExpr(ParamIdx);
  if (!ArgE)
    return;

  const MemRegion *BaseR = getBaseRegionFromExpr(ArgE, C);
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();
  BaseR = canonicalizeBase(BaseR, State);
  if (!BaseR)
    return;

  State = setFieldReleased(State, BaseR, FieldMask);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    return;
  }

  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  // 1) Track aliasing for pointer variables: p2 = p1;
  if (const VarRegion *LHSVar = dyn_cast<VarRegion>(LHSReg)) {
    // Ensure it's a pointer-to-struct variable.
    if (isStructPointerVarRegion(LHSVar, C)) {
      if (const MemRegion *RHSReg = Val.getAsRegion()) {
        RHSReg = RHSReg->getBaseRegion();
        if (RHSReg) {
          const MemRegion *Root = canonicalizeBase(RHSReg, State);
          if (!Root)
            Root = RHSReg;
          // Map LHSVar to root
          State = State->set<PtrAliasMap>(LHSVar, Root);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // 2) If writing to a field like device->bdev_file = ..., clear the released bit.
  if (const FieldRegion *FR = dyn_cast<FieldRegion>(LHSReg)) {
    const FieldDecl *FD = FR->getDecl();
    if (FD && FD->getName() == "bdev_file") {
      const MemRegion *Base = FR->getSuperRegion();
      if (Base)
        Base = Base->getBaseRegion();
      if (Base) {
        Base = canonicalizeBase(Base, State);
        if (Base) {
          State = clearFieldReleased(State, Base, BDEV_FILE_BIT);
          C.addTransition(State);
          return;
        }
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition)
    return;

  const MemRegion *BaseR = nullptr;
  unsigned FieldBit = 0;
  if (!getFieldAccessInfo(dyn_cast<Expr>(Condition), C, BaseR, FieldBit))
    return;

  if (FieldBit != BDEV_FILE_BIT)
    return;

  ProgramStateRef State = C.getState();
  const unsigned *Mask = State->get<ReleasedFieldMap>(BaseR);
  if (!Mask)
    return;

  if ((*Mask & BDEV_FILE_BIT) == 0)
    return;

  reportAtCondition(Condition, C, "Stale file* checked after close; set field to NULL after close");
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isSecondUseFunction(Call, C))
    return;

  if (Call.getNumArgs() == 0)
    return;

  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return;

  const MemRegion *BaseR = nullptr;
  unsigned FieldBit = 0;
  if (!getFieldAccessInfo(ArgE, C, BaseR, FieldBit))
    return;

  if (FieldBit != BDEV_FILE_BIT)
    return;

  ProgramStateRef State = C.getState();
  const unsigned *Mask = State->get<ReleasedFieldMap>(BaseR);
  if (!Mask)
    return;

  if ((*Mask & BDEV_FILE_BIT) == 0)
    return;

  reportAtCall(Call, C, "Double close/fput on freed struct file* field");
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects stale struct file* field usage after close; suggests setting field to NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
