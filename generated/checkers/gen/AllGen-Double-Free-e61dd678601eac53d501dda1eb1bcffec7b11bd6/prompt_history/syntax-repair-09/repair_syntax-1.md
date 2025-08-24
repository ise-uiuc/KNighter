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
#include "llvm/ADT/ImmutableSet.h"
#include "llvm/ADT/SmallVector.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state customization
using FieldIdSet = llvm::ImmutableSet<const IdentifierInfo *>;
REGISTER_SET_FACTORY_WITH_PROGRAMSTATE(FieldIdSet)

REGISTER_MAP_WITH_PROGRAMSTATE(ObjFreedFieldsMap, const MemRegion*, FieldIdSet)
REGISTER_MAP_WITH_PROGRAMSTATE(ObjNullifiedFieldsMap, const MemRegion*, FieldIdSet)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

struct CompositeCleanupSpec {
  const char *Name;
  unsigned ObjParamIndex;
  llvm::SmallVector<const char*, 4> FreesFields;
};

// Minimal knowledge base for the target pattern.
static const CompositeCleanupSpec CleanupTable[] = {
  { "bch2_free_super", 0, {"buckets_nouse"} },
};

class SAGenTestChecker : public Checker<
                           check::PreCall,
                           check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free in teardown", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

   private:

      // Helpers
      static bool callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C);

      const MemRegion* getCanonicalBase(const MemRegion *R, ProgramStateRef State) const;

      const MemRegion* getRootBaseRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C) const;
      const MemRegion* resolveBaseRegionFromArgExpr(const Expr *E, CheckerContext &C) const;

      const IdentifierInfo* getFieldIdFromExpr(const Expr *E) const;

      template <typename MapT>
      ProgramStateRef addFieldToSet(ProgramStateRef St, const MemRegion *Base,
                                    const IdentifierInfo *FieldId) const {
        if (!Base || !FieldId)
          return St;
        auto &F = St->get_context<FieldIdSet>();
        FieldIdSet Cur = F.getEmptySet();
        if (const FieldIdSet *Existing = St->get<MapT>(Base))
          Cur = *Existing;
        Cur = F.add(Cur, FieldId);
        return St->set<MapT>(Base, Cur);
      }

      template <typename MapT>
      bool setContainsField(ProgramStateRef St, const MemRegion *Base,
                            StringRef FieldName) const {
        if (!Base)
          return false;
        if (const FieldIdSet *S = St->get<MapT>(Base)) {
          for (const IdentifierInfo *II : *S) {
            if (II && II->getName() == FieldName)
              return true;
          }
        }
        return false;
      }

      template <typename MapT>
      ProgramStateRef removeFieldFromSetByName(ProgramStateRef St, const MemRegion *Base,
                                               StringRef FieldName) const {
        if (!Base)
          return St;
        if (const FieldIdSet *S = St->get<MapT>(Base)) {
          auto &F = St->get_context<FieldIdSet>();
          FieldIdSet Cur = *S;
          for (const IdentifierInfo *II : *S) {
            if (II && II->getName() == FieldName) {
              Cur = F.remove(Cur, II);
              break;
            }
          }
          return St->set<MapT>(Base, Cur);
        }
        return St;
      }

      void reportDoubleFree(CheckerContext &C, const CallEvent &Call,
                            StringRef FieldName, StringRef CalleeName) const;
};

bool SAGenTestChecker::callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, Name, C);
}

const MemRegion* SAGenTestChecker::getCanonicalBase(const MemRegion *R, ProgramStateRef State) const {
  if (!R) return nullptr;
  const MemRegion *Cur = R->getBaseRegion();
  // Follow alias chains to a fixed point.
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur) {
    if (!Visited.insert(Cur).second)
      break;
    const MemRegion *Next = State->get<PtrAliasMap>(Cur);
    if (!Next || Next == Cur)
      break;
    Cur = Next->getBaseRegion();
  }
  return Cur;
}

const MemRegion* SAGenTestChecker::getRootBaseRegionFromMemberExpr(const MemberExpr *ME, CheckerContext &C) const {
  if (!ME) return nullptr;
  const Expr *BaseE = ME->getBase(); // Do not ignore implicit before region query (per suggestion)
  const MemRegion *R = getMemRegionFromExpr(BaseE, C);
  if (!R) return nullptr;
  ProgramStateRef State = C.getState();
  return getCanonicalBase(R, State);
}

const MemRegion* SAGenTestChecker::resolveBaseRegionFromArgExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;

  // Prefer member expression (including inside unary & or casts).
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    return getRootBaseRegionFromMemberExpr(ME, C);
  }

  // Otherwise, try direct region from E (could be a declref of object pointer)
  const MemRegion *R = getMemRegionFromExpr(E, C);
  if (!R)
    return nullptr;

  ProgramStateRef State = C.getState();
  return getCanonicalBase(R, State);
}

const IdentifierInfo* SAGenTestChecker::getFieldIdFromExpr(const Expr *E) const {
  if (!E) return nullptr;
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(E)) {
    if (const ValueDecl *MD = ME->getMemberDecl()) {
      return MD->getIdentifier();
    }
  }
  return nullptr;
}

void SAGenTestChecker::reportDoubleFree(CheckerContext &C, const CallEvent &Call,
                                        StringRef FieldName, StringRef CalleeName) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "Double free: member '";
  Msg += FieldName;
  Msg += "' freed again by '";
  Msg += CalleeName;
  Msg += "'";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track pointer aliasing: LHS region aliases RHS region.
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    LHSReg = LHSReg->getBaseRegion();
    if (LHSReg) {
      if (const MemRegion *RHSReg = Val.getAsRegion()) {
        RHSReg = RHSReg->getBaseRegion();
        if (RHSReg) {
          State = State->set<PtrAliasMap>(LHSReg, RHSReg);
          State = State->set<PtrAliasMap>(RHSReg, LHSReg);
        }
      }
    }
  }

  // Track nullifications of object members: obj->field = NULL;
  const auto *BO = S ? findSpecificTypeInChildren<BinaryOperator>(S) : nullptr;
  if (BO && BO->isAssignmentOp()) {
    const Expr *LHS = BO->getLHS();
    const Expr *RHS = BO->getRHS();
    const auto *ME = LHS ? dyn_cast<MemberExpr>(LHS->IgnoreParenCasts()) : nullptr;

    bool RHSIsZero = false;
    if (RHS) {
      SVal RHSVal = State->getSVal(RHS, C.getLocationContext());
      if (auto CI = RHSVal.getAs<nonloc::ConcreteInt>())
        RHSIsZero = CI->getValue().isZero();
      else
        RHSIsZero = RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
    } else {
      // Fallback to the Val passed to checkBind.
      if (auto CI = Val.getAs<nonloc::ConcreteInt>())
        RHSIsZero = CI->getValue().isZero();
    }

    if (ME && RHSIsZero) {
      const MemRegion *Base = getRootBaseRegionFromMemberExpr(ME, C);
      const IdentifierInfo *FieldId = ME->getMemberDecl() ? ME->getMemberDecl()->getIdentifier() : nullptr;
      if (Base && FieldId) {
        State = addFieldToSet<ObjNullifiedFieldsMap>(State, Base, FieldId);
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // 1) Record manual frees: kfree-like calls on object members.
  if (callHasName(Call, "kfree", C) ||
      callHasName(Call, "kvfree", C) ||
      callHasName(Call, "kfree_sensitive", C) ||
      callHasName(Call, "vfree", C)) {

    if (Call.getNumArgs() >= 1) {
      const Expr *Arg0 = Call.getArgExpr(0);
      const IdentifierInfo *FieldId = getFieldIdFromExpr(Arg0);
      if (!FieldId)
        return; // only consider freeing object members

      const MemRegion *Base = resolveBaseRegionFromArgExpr(Arg0, C);
      if (!Base)
        return;

      Base = getCanonicalBase(Base, State);
      if (!Base)
        return;

      State = addFieldToSet<ObjFreedFieldsMap>(State, Base, FieldId);
      C.addTransition(State);
    }
    return;
  }

  // 2) Detect composite-cleanup frees of already-freed members.
  for (const auto &Spec : CleanupTable) {
    if (!callHasName(Call, Spec.Name, C))
      continue;

    if (Call.getNumArgs() <= Spec.ObjParamIndex)
      continue;

    const Expr *ObjArg = Call.getArgExpr(Spec.ObjParamIndex);
    const MemRegion *Base = resolveBaseRegionFromArgExpr(ObjArg, C);
    if (!Base)
      continue;

    Base = getCanonicalBase(Base, State);
    if (!Base)
      continue;

    // Check each field the helper frees.
    for (const char *FieldNameCStr : Spec.FreesFields) {
      StringRef FieldName(FieldNameCStr);
      bool WasFreed = setContainsField<ObjFreedFieldsMap>(State, Base, FieldName);
      bool WasNullified = setContainsField<ObjNullifiedFieldsMap>(State, Base, FieldName);

      if (WasFreed && !WasNullified) {
        reportDoubleFree(C, Call, FieldName, Spec.Name);
        // Optional: remove the field to avoid duplicate reports on same path.
        State = removeFieldFromSetByName<ObjFreedFieldsMap>(State, Base, FieldName);
        C.addTransition(State);
        return; // report once per helper call
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when a member is manually freed and later freed again by a composite cleanup helper",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 26 | REGISTER_SET_FACTORY_WITH_PROGRAMSTATE(FieldIdSet)

	- Error Messages: macro "REGISTER_SET_FACTORY_WITH_PROGRAMSTATE" requires 2 arguments, but only 1 given

- Error Line: 26 | REGISTER_SET_FACTORY_WITH_PROGRAMSTATE(FieldIdSet)

	- Error Messages: ‘REGISTER_SET_FACTORY_WITH_PROGRAMSTATE’ does not name a type

- Error Line: 28 | REGISTER_MAP_WITH_PROGRAMSTATE(ObjFreedFieldsMap, const MemRegion*, FieldIdSet)

	- Error Messages: ‘ObjFreedFieldsMap’ was not declared in this scope

- Error Line: 42 |   struct ProgramStateTrait<Name> : public ProgramStatePartialTrait<Name##Ty> { \

	- Error Messages: template argument 1 is invalid

- Error Line: 28 | REGISTER_MAP_WITH_PROGRAMSTATE(ObjFreedFieldsMap, const MemRegion*, FieldIdSet)

	- Error Messages: ‘ObjFreedFieldsMapTy’ was not declared in this scope

- Error Line: 42 |   struct ProgramStateTrait<Name> : public ProgramStatePartialTrait<Name##Ty> { \

	- Error Messages: template argument 1 is invalid

- Error Line: 52 |   typedef typename T::data_type data_type;

	- Error Messages: no type named ‘data_type’ in ‘class llvm::ImmutableSet<const clang::IdentifierInfo*>’

- Error Line: 73 |         auto &F = St->get_context<FieldIdSet>();

	- Error Messages: no matching function for call to ‘clang::ento::ProgramState::get_context<FieldIdSet>() const’

- Error Line: 101 |           auto &F = St->get_context<FieldIdSet>();

	- Error Messages: no matching function for call to ‘clang::ento::ProgramState::get_context<FieldIdSet>() const’

- Error Line: 848 | typename ProgramStateTrait<T>::context_type ProgramState::get_context() const {

	- Error Messages: no type named ‘context_type’ in ‘struct clang::ento::ProgramStateTrait<llvm::ImmutableSet<const clang::IdentifierInfo*> >’

- Error Line: 133 |     const MemRegion *Next = State->get<PtrAliasMap>(Cur);

	- Error Messages: cannot convert ‘clang::ento::ProgramStatePartialTrait<llvm::ImmutableMap<const clang::ento::MemRegion*, const clang::ento::MemRegion*> >::lookup_type’ {aka ‘const clang::ento::MemRegion* const*’} to ‘const clang::ento::MemRegion*’ in initialization

- Error Line: 271 |       State = addFieldToSet<ObjFreedFieldsMap>(State, Base, FieldId);

	- Error Messages: ‘ObjFreedFieldsMap’ was not declared in this scope; did you mean ‘ObjNullifiedFieldsMap’?

- Error Line: 271 |       State = addFieldToSet<ObjFreedFieldsMap>(State, Base, FieldId);

	- Error Messages: no matching function for call to ‘{anonymous}::SAGenTestChecker::addFieldToSet<<expression error> >(clang::ento::ProgramStateRef&, const clang::ento::MemRegion*&, const clang::IdentifierInfo*&) const’

- Error Line: 271 |       State = addFieldToSet<ObjFreedFieldsMap>(State, Base, FieldId);

	- Error Messages: template argument 1 is invalid

- Error Line: 297 |       bool WasFreed = setContainsField<ObjFreedFieldsMap>(State, Base, FieldName);

	- Error Messages: ‘ObjFreedFieldsMap’ was not declared in this scope; did you mean ‘ObjNullifiedFieldsMap’?

- Error Line: 297 |       bool WasFreed = setContainsField<ObjFreedFieldsMap>(State, Base, FieldName);

	- Error Messages: no matching function for call to ‘{anonymous}::SAGenTestChecker::setContainsField<<expression error> >(clang::ento::ProgramStateRef&, const clang::ento::MemRegion*&, llvm::StringRef&) const’

- Error Line: 297 |       bool WasFreed = setContainsField<ObjFreedFieldsMap>(State, Base, FieldName);

	- Error Messages: template argument 1 is invalid

- Error Line: 303 |         State = removeFieldFromSetByName<ObjFreedFieldsMap>(State, Base, FieldName);

	- Error Messages: no matching function for call to ‘{anonymous}::SAGenTestChecker::removeFieldFromSetByName<ObjFreedFieldsMap>(clang::ento::ProgramStateRef&, const clang::ento::MemRegion*&, llvm::StringRef&) const’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
