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
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/ImmutableSet.h"
#include "llvm/ADT/SmallVector.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_SET_WITH_PROGRAMSTATE(FreedFieldRegionSet, const FieldRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasBaseMap, const MemRegion *, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasFieldMap, const MemRegion *, const FieldDecl *)

namespace {

class SAGenTestChecker
    : public Checker<
          check::PreCall,
          check::PostCall,
          check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double free of struct member", "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C);
  static bool isKfreeLike(const CallEvent &Call, CheckerContext &C);

  struct CompositeSpec {
    unsigned BaseParamIndex = 0;
    llvm::SmallVector<StringRef, 4> Members;
  };
  static bool isCompositeCleanup(const CallEvent &Call, CheckerContext &C,
                                 CompositeSpec &Out);

  static bool getMemberFromExpr(const Expr *E, CheckerContext &C,
                                const MemRegion *&OutBase,
                                const FieldDecl *&OutField);

  static const MemRegion *getVarRegionFromExpr(const Expr *E, CheckerContext &C);

  static const FieldDecl *lookupFieldInPointee(QualType PtrTy, StringRef Name);

  static const FieldRegion *getFieldRegionFor(const MemRegion *Base,
                                              const FieldDecl *FD,
                                              CheckerContext &C);

  static bool wasFreed(ProgramStateRef State, const MemRegion *Base,
                       const FieldDecl *FD, CheckerContext &C);
  static ProgramStateRef setFreed(ProgramStateRef State, const MemRegion *Base,
                                  const FieldDecl *FD, CheckerContext &C);

  static ProgramStateRef clearAliasFor(ProgramStateRef State, const MemRegion *PtrReg);

  void reportDoubleFree(CheckerContext &C, StringRef Msg,
                        SourceRange R) const;
};

// Implementation

bool SAGenTestChecker::callHasName(const CallEvent &Call, StringRef Name,
                                   CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, Name, C);
}

bool SAGenTestChecker::isKfreeLike(const CallEvent &Call, CheckerContext &C) {
  return callHasName(Call, "kfree", C) ||
         callHasName(Call, "kvfree", C) ||
         callHasName(Call, "vfree", C) ||
         callHasName(Call, "kfree_sensitive", C);
}

bool SAGenTestChecker::isCompositeCleanup(const CallEvent &Call, CheckerContext &C,
                                          CompositeSpec &Out) {
  struct Entry {
    const char *Name;
    unsigned BaseParamIndex;
    const char *Members[4];
    unsigned NumMembers;
  };
  static const Entry Table[] = {
      {"bch2_dev_buckets_free", 0, {"buckets_nouse"}, 1},
  };

  for (const auto &E : Table) {
    if (callHasName(Call, E.Name, C)) {
      Out.BaseParamIndex = E.BaseParamIndex;
      Out.Members.clear();
      for (unsigned i = 0; i < E.NumMembers; ++i)
        Out.Members.push_back(E.Members[i]);
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::getMemberFromExpr(const Expr *E, CheckerContext &C,
                                         const MemRegion *&OutBase,
                                         const FieldDecl *&OutField) {
  OutBase = nullptr;
  OutField = nullptr;
  if (!E)
    return false;

  // Find a MemberExpr inside the expression
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(E);
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  const auto *FD = dyn_cast<FieldDecl>(VD);
  if (!FD)
    return false;

  const Expr *BaseE = ME->getBase();
  if (!BaseE)
    return false;

  const MemRegion *BaseReg = getMemRegionFromExpr(BaseE, C);
  if (!BaseReg)
    return false;

  BaseReg = BaseReg->getBaseRegion();
  if (!BaseReg)
    return false;

  OutBase = BaseReg;
  OutField = FD;
  return true;
}

const MemRegion *SAGenTestChecker::getVarRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const Expr *EE = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(EE)) {
    const MemRegion *R = getMemRegionFromExpr(DRE, C);
    if (!R)
      return nullptr;
    return R->getBaseRegion();
  }
  return nullptr;
}

const FieldDecl *SAGenTestChecker::lookupFieldInPointee(QualType PtrTy, StringRef Name) {
  if (PtrTy.isNull())
    return nullptr;
  if (!PtrTy->isPointerType())
    return nullptr;

  QualType Pointee = PtrTy->getPointeeType();
  if (Pointee.isNull())
    return nullptr;

  const RecordType *RT = dyn_cast<RecordType>(Pointee.getTypePtr());
  if (!RT)
    return nullptr;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return nullptr;

  for (const FieldDecl *FD : RD->fields()) {
    if (FD && FD->getName() == Name)
      return FD;
  }
  return nullptr;
}

const FieldRegion *SAGenTestChecker::getFieldRegionFor(const MemRegion *Base,
                                                       const FieldDecl *FD,
                                                       CheckerContext &C) {
  if (!Base || !FD)
    return nullptr;
  const auto *Super = dyn_cast<SubRegion>(Base);
  if (!Super)
    return nullptr;
  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  return MRMgr.getFieldRegion(FD, Super);
}

bool SAGenTestChecker::wasFreed(ProgramStateRef State, const MemRegion *Base,
                                const FieldDecl *FD, CheckerContext &C) {
  if (!State || !Base || !FD)
    return false;
  const FieldRegion *FR = getFieldRegionFor(Base, FD, C);
  if (!FR)
    return false;
  return State->contains<FreedFieldRegionSet>(FR);
}

ProgramStateRef SAGenTestChecker::setFreed(ProgramStateRef State,
                                           const MemRegion *Base,
                                           const FieldDecl *FD,
                                           CheckerContext &C) {
  if (!State || !Base || !FD)
    return State;
  const FieldRegion *FR = getFieldRegionFor(Base, FD, C);
  if (!FR)
    return State;
  return State->add<FreedFieldRegionSet>(FR);
}

ProgramStateRef SAGenTestChecker::clearAliasFor(ProgramStateRef State, const MemRegion *PtrReg) {
  if (!State || !PtrReg)
    return State;
  State = State->remove<PtrAliasBaseMap>(PtrReg);
  State = State->remove<PtrAliasFieldMap>(PtrReg);
  return State;
}

void SAGenTestChecker::reportDoubleFree(CheckerContext &C, StringRef Msg,
                                        SourceRange R) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (R.isValid())
    Report->addRange(R);
  C.emitReport(std::move(Report));
}

// Callbacks

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg) {
    C.addTransition(State);
    return;
  }

  const Expr *RHSExpr = nullptr;

  // Try to extract RHS from the statement if possible.
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign)
      RHSExpr = BO->getRHS();
  } else if (const auto *DS = dyn_cast_or_null<DeclStmt>(S)) {
    // For declaration with initializer: int *p = ...;
    if (const auto *VR = dyn_cast<VarRegion>(LHSReg)) {
      const VarDecl *LHSVD = VR->getDecl();
      for (const Decl *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (VD == LHSVD) {
            RHSExpr = VD->getInit();
            break;
          }
        }
      }
    }
  }

  bool DidAlias = false;

  if (RHSExpr) {
    // Case 1: p = ca->member;
    const MemRegion *Base = nullptr;
    const FieldDecl *FD = nullptr;
    if (getMemberFromExpr(RHSExpr, C, Base, FD)) {
      if (Base && FD) {
        State = State->set<PtrAliasBaseMap>(LHSReg, Base);
        State = State->set<PtrAliasFieldMap>(LHSReg, FD);
        DidAlias = true;
      }
    } else {
      // Case 2: p = q; copy alias if q is known
      const MemRegion *RHSReg = getVarRegionFromExpr(RHSExpr, C);
      if (RHSReg && RHSReg != LHSReg) {
        RHSReg = RHSReg->getBaseRegion();
        const MemRegion *AliasedBase = nullptr;
        const FieldDecl *AliasedField = nullptr;
        if (const MemRegion *const *AB = State->get<PtrAliasBaseMap>(RHSReg))
          AliasedBase = *AB;
        if (const FieldDecl *const *AF = State->get<PtrAliasFieldMap>(RHSReg))
          AliasedField = *AF;
        if (AliasedBase && AliasedField) {
          State = State->set<PtrAliasBaseMap>(LHSReg, AliasedBase);
          State = State->set<PtrAliasFieldMap>(LHSReg, AliasedField);
          DidAlias = true;
        }
      }
    }
  }

  if (!DidAlias) {
    // Not an alias to a tracked member. Clear any stale alias info.
    State = clearAliasFor(State, LHSReg);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isKfreeLike(Call, C))
    return;

  ProgramStateRef State = C.getState();

  if (Call.getNumArgs() < 1) {
    C.addTransition(State);
    return;
  }

  const Expr *E0 = Call.getArgExpr(0);
  const MemRegion *Base = nullptr;
  const FieldDecl *FD = nullptr;

  // Direct form: kfree(ca->member)
  if (getMemberFromExpr(E0, C, Base, FD)) {
    if (Base && FD) {
      if (wasFreed(State, Base, FD, C)) {
        SmallString<128> Msg;
        Msg += "Double free of struct member '";
        Msg += FD->getName();
        Msg += "'.";
        reportDoubleFree(C, Msg, E0 ? E0->getSourceRange() : SourceRange());
        return;
      }
      State = setFreed(State, Base, FD, C);
      C.addTransition(State);
      return;
    }
  }

  // Aliased form: p aliases ca->member; kfree(p)
  const MemRegion *PtrReg = getVarRegionFromExpr(E0, C);
  if (PtrReg) {
    PtrReg = PtrReg->getBaseRegion();
    const MemRegion *AliasedBase = nullptr;
    const FieldDecl *AliasedField = nullptr;
    if (const MemRegion *const *AB = State->get<PtrAliasBaseMap>(PtrReg))
      AliasedBase = *AB;
    if (const FieldDecl *const *AF = State->get<PtrAliasFieldMap>(PtrReg))
      AliasedField = *AF;
    if (AliasedBase && AliasedField) {
      if (wasFreed(State, AliasedBase, AliasedField, C)) {
        SmallString<128> Msg;
        Msg += "Double free of struct member '";
        Msg += AliasedField->getName();
        Msg += "'.";
        reportDoubleFree(C, Msg, E0 ? E0->getSourceRange() : SourceRange());
        return;
      }
      State = setFreed(State, AliasedBase, AliasedField, C);
      C.addTransition(State);
      return;
    }
  }

  // Not a tracked case; proceed.
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  CompositeSpec Spec;
  if (!isCompositeCleanup(Call, C, Spec)) {
    C.addTransition(State);
    return;
  }

  if (Call.getNumArgs() <= Spec.BaseParamIndex) {
    C.addTransition(State);
    return;
  }

  const Expr *BaseArg = Call.getArgExpr(Spec.BaseParamIndex);
  if (!BaseArg) {
    C.addTransition(State);
    return;
  }

  const MemRegion *BaseReg = getMemRegionFromExpr(BaseArg, C);
  if (!BaseReg) {
    C.addTransition(State);
    return;
  }
  BaseReg = BaseReg->getBaseRegion();
  if (!BaseReg) {
    C.addTransition(State);
    return;
  }

  QualType BaseTy = BaseArg->getType();
  for (StringRef Name : Spec.Members) {
    const FieldDecl *FD = lookupFieldInPointee(BaseTy, Name);
    if (!FD)
      continue;

    if (wasFreed(State, BaseReg, FD, C)) {
      SmallString<160> Msg;
      Msg += "Double free: member '";
      Msg += FD->getName();
      Msg += "' already freed before calling '";
      // Try to get the function name from the origin expr
      if (const Expr *OE = Call.getOriginExpr()) {
        const SourceManager &SM = C.getSourceManager();
        const LangOptions &LO = C.getLangOpts();
        StringRef Text = Lexer::getSourceText(
            CharSourceRange::getTokenRange(OE->getSourceRange()), SM, LO);
        // Best effort; do not overcomplicate extracting just the callee identifier.
        if (!Text.empty())
          Msg += Text.split('(').first; // take token before '('
        else
          Msg += "composite";
      } else {
        Msg += "composite";
      }
      Msg += "'.";
      reportDoubleFree(C, Msg, Call.getSourceRange());
      // Keep modeling anyway
    }

    State = setFreed(State, BaseReg, FD, C);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when a struct member is kfree'd and later freed again by a composite cleanup helper",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
