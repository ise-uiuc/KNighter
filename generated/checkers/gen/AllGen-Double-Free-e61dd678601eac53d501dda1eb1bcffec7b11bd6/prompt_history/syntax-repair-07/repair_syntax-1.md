## Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

## Instruction

The following checker fails to compile, and your task is to resolve the compilation error based on the provided error messages.

Here are some potential ways to fix the issue:

1. Use the correct API: The current API may not exist, or the class has no such member. Replace it with an appropriate one.

2. Use correct arguments: Ensure the arguments passed to the API have the correct types and the correct number.

3. Change the variable types: Adjust the types of some variables based on the error messages.

4. Be careful if you want to include a header file. Please make sure the header file exists. For instance "fatal error: clang/StaticAnalyzer/Core/PathDiagnostic.h: No such file or directory".

**The version of Clang environment is Clang-18. You should consider the API compatibility.**

**Please only repair the failed parts and keep the original semantics.**
**Please return the whole checker code after fixing the compilation error.**

## Suggestions

1. Please only use two types of bug reports:
  - BasicBugReport (const BugType &bt, StringRef desc, PathDiagnosticLocation l)
  - PathSensitiveBugReport (const BugType &bt, StringRef desc, const ExplodedNode *errorNode)
  - PathSensitiveBugReport (const BugType &bt, StringRef shortDesc, StringRef desc, const ExplodedNode *errorNode)

## Example

- Error Line: 48 |   Optional<DefinedOrUnknownSVal> SizeSVal;

  - Error Messages: ‘Optional’ was not declared in this scope; did you mean ‘clang::ObjCImplementationControl::Optional’?

  - Fix: Replace 'Optional<DefinedOrUnknownSVal>' with 'std::optional<DefinedOrUnknownSVal>', and include the appropriate header.

- Error Line: 113 |     const MemRegion *MR = Entry.first;

    - Error Messages: unused variable ‘MR’ [-Wunused-variable]

    - Fix: Remove the variable 'MR' if it is not used.

## Checker

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
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/ImmutableSet.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
using FieldSet = llvm::ImmutableSet<const FieldDecl *>;
REGISTER_MAP_WITH_PROGRAMSTATE(FreedFieldPerBaseMap, const MemRegion *, FieldSet)
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

  static bool wasFreed(ProgramStateRef State, const MemRegion *Base,
                       const FieldDecl *FD);
  static ProgramStateRef setFreed(ProgramStateRef State, const MemRegion *Base,
                                  const FieldDecl *FD);

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

bool SAGenTestChecker::wasFreed(ProgramStateRef State, const MemRegion *Base,
                                const FieldDecl *FD) {
  if (!State || !Base || !FD)
    return false;

  const FieldSet *SetPtr = State->get<FreedFieldPerBaseMap>(Base);
  if (!SetPtr)
    return false;

  FieldSet S = *SetPtr;
  return S.contains(FD);
}

ProgramStateRef SAGenTestChecker::setFreed(ProgramStateRef State,
                                           const MemRegion *Base,
                                           const FieldDecl *FD) {
  if (!State || !Base || !FD)
    return State;

  auto &Factory = State->get_context<FieldSet>();
  const FieldSet *SetPtr = State->get<FreedFieldPerBaseMap>(Base);
  FieldSet S = SetPtr ? *SetPtr : Factory.getEmptySet();
  if (!S.contains(FD)) {
    S = Factory.add(S, FD);
    State = State->set<FreedFieldPerBaseMap>(Base, S);
  }
  return State;
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
        const MemRegion *AliasedBase = State->get<PtrAliasBaseMap>(RHSReg);
        const FieldDecl *AliasedField = State->get<PtrAliasFieldMap>(RHSReg);
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
      if (wasFreed(State, Base, FD)) {
        SmallString<128> Msg;
        Msg += "Double free of struct member '";
        Msg += FD->getName();
        Msg += "'.";
        reportDoubleFree(C, Msg, E0 ? E0->getSourceRange() : SourceRange());
        return;
      }
      State = setFreed(State, Base, FD);
      C.addTransition(State);
      return;
    }
  }

  // Aliased form: p aliases ca->member; kfree(p)
  const MemRegion *PtrReg = getVarRegionFromExpr(E0, C);
  if (PtrReg) {
    PtrReg = PtrReg->getBaseRegion();
    const MemRegion *AliasedBase = State->get<PtrAliasBaseMap>(PtrReg);
    const FieldDecl *AliasedField = State->get<PtrAliasFieldMap>(PtrReg);
    if (AliasedBase && AliasedField) {
      if (wasFreed(State, AliasedBase, AliasedField)) {
        SmallString<128> Msg;
        Msg += "Double free of struct member '";
        Msg += AliasedField->getName();
        Msg += "'.";
        reportDoubleFree(C, Msg, E0 ? E0->getSourceRange() : SourceRange());
        return;
      }
      State = setFreed(State, AliasedBase, AliasedField);
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

    if (wasFreed(State, BaseReg, FD)) {
      SmallString<160> Msg;
      Msg += "Double free: member '";
      Msg += FD->getName();
      Msg += "' already freed before calling '";
      // Try to get the function name from the origin expr
      if (const Expr *OE = Call.getOriginExpr()) {
        const SourceManager &SM = C.getSourceManager();
        const LangOptions &LO = C.getLangOpts();
        StringRef Text = Lexer::getSourceText(CharSourceRange::getTokenRange(OE->getSourceRange()), SM, LO);
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

    State = setFreed(State, BaseReg, FD);
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

```

## Error Messages

- Error Line: 52 |   typedef typename T::data_type data_type;

	- Error Messages: no type named ‘data_type’ in ‘class llvm::ImmutableSet<const clang::FieldDecl*>’

- Error Line: 213 |   auto &Factory = State->get_context<FieldSet>();

	- Error Messages: no matching function for call to ‘clang::ento::ProgramState::get_context<FieldSet>() const’

- Error Line: 295 |         const MemRegion *AliasedBase = State->get<PtrAliasBaseMap>(RHSReg);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization

- Error Line: 296 |         const FieldDecl *AliasedField = State->get<PtrAliasFieldMap>(RHSReg);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::FieldDecl*> >::lookup_type’ {aka ‘const clang::FieldDecl* const*’} to ‘const clang::FieldDecl*’ in initialization

- Error Line: 350 |     const MemRegion *AliasedBase = State->get<PtrAliasBaseMap>(PtrReg);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization

- Error Line: 351 |     const FieldDecl *AliasedField = State->get<PtrAliasFieldMap>(PtrReg);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::FieldDecl*> >::lookup_type’ {aka ‘const clang::FieldDecl* const*’} to ‘const clang::FieldDecl*’ in initialization



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
