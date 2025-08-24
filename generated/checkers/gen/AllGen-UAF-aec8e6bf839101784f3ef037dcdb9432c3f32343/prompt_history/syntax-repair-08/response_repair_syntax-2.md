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
#include "clang/AST/Type.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallString.h"

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program State Customization ----------------

// Set of released fields
REGISTER_SET_WITH_PROGRAMSTATE(ReleasedFieldSet, const FieldDecl *)
// Map: Base struct pointer region -> Set of released fields
REGISTER_MAP_WITH_PROGRAMSTATE(
    BaseToReleasedFields, const MemRegion *,
    ProgramStateTrait<ReleasedFieldSet>::data_type)
// Simple alias map for pointer-to-struct aliases
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)

namespace {

struct KnownFieldReleaser {
  const char *Name;
  unsigned ParamIndex;
  const char *FieldName;
};

// Known wrapper that releases a specific field of a struct pointer parameter.
static const KnownFieldReleaser KnownFieldReleasers[] = {
    {"btrfs_close_bdev", 0, "bdev_file"},
};

class SAGenTestChecker
    : public Checker<check::PostCall, check::PostStmt<BinaryOperator>,
                     check::Bind, check::PreCall, check::BranchCondition,
                     check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() = default;

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  // Helpers
  static bool isFunctionNamed(const CallEvent &Call, StringRef Name,
                              CheckerContext &C);

  const MemRegion *resolveAlias(ProgramStateRef State,
                                const MemRegion *R) const;

  const MemRegion *getBaseVarRegion(const Expr *Base,
                                    CheckerContext &C) const;

  const FieldDecl *lookupFieldDeclFromPointee(const Expr *Base,
                                              StringRef FieldName) const;

  ProgramStateRef addReleased(ProgramStateRef State, const MemRegion *BaseR,
                              const FieldDecl *FD) const;
  ProgramStateRef removeReleased(ProgramStateRef State, const MemRegion *BaseR,
                                 const FieldDecl *FD) const;
  bool isReleased(ProgramStateRef State, const MemRegion *BaseR,
                  const FieldDecl *FD) const;

  bool isNullPtrValue(const Expr *E, CheckerContext &C) const;

  void ensureBugType(CheckerContext &C) const;

  void reportAtCall(const CallEvent &Call, CheckerContext &C,
                    StringRef Msg) const;

  void reportAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const;
};

// ---------------------- Helper Implementations ----------------------

bool SAGenTestChecker::isFunctionNamed(const CallEvent &Call, StringRef Name,
                                       CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

const MemRegion *SAGenTestChecker::resolveAlias(ProgramStateRef State,
                                                const MemRegion *R) const {
  if (!R)
    return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  // Follow a short chain to avoid cycles.
  for (unsigned i = 0; i < 8; ++i) {
    if (!Cur)
      break;
    if (const MemRegion *const *P = State->get<PtrAliasMap>(Cur)) {
      const MemRegion *Next = *P;
      if (!Next || Next == Cur)
        break;
      Cur = Next->getBaseRegion();
    } else {
      break;
    }
  }
  return Cur ? Cur->getBaseRegion() : nullptr;
}

const MemRegion *SAGenTestChecker::getBaseVarRegion(const Expr *Base,
                                                    CheckerContext &C) const {
  if (!Base)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(Base, C);
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;
  ProgramStateRef State = C.getState();
  return resolveAlias(State, MR);
}

const FieldDecl *
SAGenTestChecker::lookupFieldDeclFromPointee(const Expr *Base,
                                             StringRef FieldName) const {
  if (!Base)
    return nullptr;
  QualType QT = Base->getType();
  if (!QT.getTypePtrOrNull())
    return nullptr;

  // Expect pointer to record.
  if (!QT->isPointerType())
    return nullptr;

  QualType Pointee = QT->getPointeeType();
  if (Pointee.isNull())
    return nullptr;

  const RecordType *RT = Pointee->getAs<RecordType>();
  if (!RT)
    return nullptr;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return nullptr;

  for (const FieldDecl *FD : RD->fields()) {
    if (FD && FD->getIdentifier() &&
        FD->getName().equals(FieldName)) {
      return FD;
    }
  }
  return nullptr;
}

ProgramStateRef SAGenTestChecker::addReleased(ProgramStateRef State,
                                              const MemRegion *BaseR,
                                              const FieldDecl *FD) const {
  if (!BaseR || !FD)
    return State;

  auto &F = State->get_context<ReleasedFieldSet>();
  using SetTy = ProgramStateTrait<ReleasedFieldSet>::data_type;

  const SetTy *CurPtr = State->get<BaseToReleasedFields>(BaseR);
  SetTy Cur = CurPtr ? *CurPtr : F.getEmptySet();

  if (!Cur.contains(FD)) {
    Cur = F.add(Cur, FD);
    State = State->set<BaseToReleasedFields>(BaseR, Cur);
  }
  return State;
}

ProgramStateRef SAGenTestChecker::removeReleased(ProgramStateRef State,
                                                 const MemRegion *BaseR,
                                                 const FieldDecl *FD) const {
  if (!BaseR || !FD)
    return State;

  auto &F = State->get_context<ReleasedFieldSet>();
  using SetTy = ProgramStateTrait<ReleasedFieldSet>::data_type;

  const SetTy *CurPtr = State->get<BaseToReleasedFields>(BaseR);
  if (!CurPtr)
    return State;

  SetTy Cur = *CurPtr;
  if (Cur.contains(FD)) {
    Cur = F.remove(Cur, FD);
    if (Cur.isEmpty())
      State = State->remove<BaseToReleasedFields>(BaseR);
    else
      State = State->set<BaseToReleasedFields>(BaseR, Cur);
  }
  return State;
}

bool SAGenTestChecker::isReleased(ProgramStateRef State, const MemRegion *BaseR,
                                  const FieldDecl *FD) const {
  if (!BaseR || !FD)
    return false;

  using SetTy = ProgramStateTrait<ReleasedFieldSet>::data_type;
  const SetTy *CurPtr = State->get<BaseToReleasedFields>(BaseR);
  if (!CurPtr)
    return false;
  return CurPtr->contains(FD);
}

bool SAGenTestChecker::isNullPtrValue(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  if (E->isNullPointerConstant(C.getASTContext(),
                               Expr::NPC_ValueDependentIsNull))
    return true;

  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    if (Res == 0)
      return true;
  }
  return false;
}

void SAGenTestChecker::ensureBugType(CheckerContext &C) const {
  if (!BT) {
    BT = std::make_unique<BugType>(this,
                                   "Use-after-free due to stale pointer",
                                   "Resource Management");
  }
}

void SAGenTestChecker::reportAtCall(const CallEvent &Call, CheckerContext &C,
                                    StringRef Msg) const {
  ensureBugType(C);
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportAtStmt(const Stmt *S, CheckerContext &C,
                                    StringRef Msg) const {
  ensureBugType(C);
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// ---------------------- Checker Callbacks ----------------------

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  // 1) Wrapper releasers e.g. btrfs_close_bdev(device) releases device->bdev_file
  for (const auto &Entry : KnownFieldReleasers) {
    if (!isFunctionNamed(Call, Entry.Name, C))
      continue;

    if (Entry.ParamIndex >= Call.getNumArgs())
      continue;

    const Expr *Arg = Call.getArgExpr(Entry.ParamIndex);
    if (!Arg)
      continue;

    const MemRegion *BaseR = getBaseVarRegion(Arg, C);
    const FieldDecl *FD = lookupFieldDeclFromPointee(Arg, Entry.FieldName);
    if (BaseR && FD) {
      State = addReleased(State, BaseR, FD);
      Changed = true;
    }
  }

  // 2) Direct release calls, e.g., fput(dev->bdev_file)
  if (isFunctionNamed(Call, "fput", C) && Call.getNumArgs() >= 1) {
    const Expr *Arg0 = Call.getArgExpr(0);
    if (Arg0) {
      const Expr *E = Arg0->IgnoreParenCasts();
      if (const auto *ME = dyn_cast<MemberExpr>(E)) {
        const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
        if (FD) {
          const MemRegion *BaseR = getBaseVarRegion(ME->getBase(), C);
          if (BaseR) {
            State = addReleased(State, BaseR, FD);
            Changed = true;
          }
        }
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPostStmt(const BinaryOperator *BO,
                                     CheckerContext &C) const {
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCacts();

  const auto *ME = dyn_cast<MemberExpr>(LHS);
  if (!ME)
    return;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return;

  const MemRegion *BaseR = getBaseVarRegion(ME->getBase(), C);
  if (!BaseR)
    return;

  ProgramStateRef State = C.getState();
  bool WasReleased = isReleased(State, BaseR, FD);
  if (!WasReleased) {
    // Even if it wasn't released, re-assignment means not stale anymore:
    // Keep state unchanged.
    return;
  }

  // Any assignment to this member (NULL or non-NULL) clears the "released" mark
  // because the original stale pointer is no longer present.
  State = removeReleased(State, BaseR, FD);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  // Track simple pointer-to-struct aliasing through assignments: p2 = p1;
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHSExpr = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHSExpr = BO->getRHS()->IgnoreParenImpCasts();
  if (!LHSExpr || !RHSExpr)
    return;

  QualType LHSTy = LHSExpr->getType();
  QualType RHSTy = RHSExpr->getType();
  if (LHSTy.isNull() || RHSTy.isNull())
    return;

  // Only track pointer-to-struct aliases
  if (!LHSTy->isPointerType() || !RHSTy->isPointerType())
    return;
  QualType LPointee = LHSTy->getPointeeType();
  QualType RPointee = RHSTy->getPointeeType();
  if (LPointee.isNull() || RPointee.isNull())
    return;
  if (!LPointee->isRecordType() || !RPointee->isRecordType())
    return;

  const MemRegion *LHSReg = getMemRegionFromExpr(LHSExpr, C);
  const MemRegion *RHSReg = getMemRegionFromExpr(RHSExpr, C);
  if (!LHSReg || !RHSReg)
    return;

  LHSReg = LHSReg->getBaseRegion();
  RHSReg = RHSReg->getBaseRegion();
  if (!LHSReg || !RHSReg)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Root = resolveAlias(State, RHSReg);
  if (!Root)
    Root = RHSReg;

  State = State->set<PtrAliasMap>(LHSReg, Root);
  State = State->set<PtrAliasMap>(Root, Root); // Canonicalize root to itself
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check each argument; if it is a MemberExpr and previously released, warn.
  for (unsigned i = 0, e = Call.getNumArgs(); i != e; ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    const Expr *E = ArgE->IgnoreParenCasts();
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME)
      continue;

    const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      continue;

    const MemRegion *BaseR = getBaseVarRegion(ME->getBase(), C);
    if (!BaseR)
      continue;

    if (!isReleased(State, BaseR, FD))
      continue;

    // If calling fput again with the stale field -> double close
    if (isFunctionNamed(Call, "fput", C)) {
      reportAtCall(Call, C, "Double close: calling 'fput' on stale struct member");
      continue;
    }

    // Otherwise, if known to dereference this argument -> UAF
    llvm::SmallVector<unsigned, 4> DerefParams;
    if (functionKnownToDeref(Call, DerefParams)) {
      for (unsigned Idx : DerefParams) {
        if (Idx == i) {
          reportAtCall(Call, C, "Use-after-free: dereferencing stale struct member");
          break;
        }
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  CondE = CondE->IgnoreParenImpCasts();

  const auto CheckMember = [&](const MemberExpr *ME) {
    if (!ME)
      return;
    const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return;
    const MemRegion *BaseR = getBaseVarRegion(ME->getBase(), C);
    if (!BaseR)
      return;
    if (isReleased(C.getState(), BaseR, FD)) {
      reportAtStmt(Condition, C,
                   "Stale struct member used in condition; not set to NULL after close");
    }
  };

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *ME = dyn_cast<MemberExpr>(Sub))
        CheckMember(ME);
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      const MemberExpr *LME = dyn_cast<MemberExpr>(L);
      const MemberExpr *RME = dyn_cast<MemberExpr>(R);
      bool LIsNull = L->isNullPointerConstant(C.getASTContext(),
                                              Expr::NPC_ValueDependentIsNull);
      bool RIsNull = R->isNullPointerConstant(C.getASTContext(),
                                              Expr::NPC_ValueDependentIsNull);

      if (LME && RIsNull)
        CheckMember(LME);
      else if (RME && LIsNull)
        CheckMember(RME);
    }
  } else {
    if (const auto *ME = dyn_cast<MemberExpr>(CondE))
      CheckMember(ME);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  using MapTy = ProgramStateTrait<BaseToReleasedFields>::data_type;
  using SetTy = ProgramStateTrait<ReleasedFieldSet>::data_type;

  MapTy Map = State->get<BaseToReleasedFields>();
  if (Map.isEmpty())
    return;

  for (auto It = Map.begin(); It != Map.end(); ++It) {
    const MemRegion *BaseR = It->first;
    const SetTy &Set = It->second;
    for (auto SIt = Set.begin(); SIt != Set.end(); ++SIt) {
      const FieldDecl *FD = *SIt;
      if (!FD)
        continue;
      // Report per stale field at function exit.
      llvm::SmallString<128> Msg;
      Msg += "Field '";
      Msg += FD->getName();
      Msg += "' released but not set to NULL before function exit";

      reportAtStmt(RS ? static_cast<const Stmt *>(RS)
                      : C.getLocationContext()->getDecl()->getBody(),
                   C, Msg);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects stale struct member pointers not nullified after close/free, "
      "leading to double-close/UAF",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
