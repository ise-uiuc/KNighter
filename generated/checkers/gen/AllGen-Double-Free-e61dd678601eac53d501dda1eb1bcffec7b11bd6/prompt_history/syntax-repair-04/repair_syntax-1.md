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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallVector.h"
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

// We store for each base object region the set of its fields that have been
// manually freed (via kfree/kvfree/etc).
REGISTER_SET_WITH_PROGRAMSTATE(FreedFieldSet, const FieldDecl*)
REGISTER_MAP_WITH_PROGRAMSTATE(ManualFreedMap, const MemRegion*, FreedFieldSetTy)

namespace {

struct CleanupSpec {
  const char *FuncName;
  unsigned ObjParamIndex;
  llvm::SmallVector<const char *, 4> FreedFields;
};

static const CleanupSpec CleanupTable[] = {
    {"bch2_dev_buckets_free", 0, {"buckets_nouse"}}
};

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double free: manual free then cleanup helper", "Memory Management")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Predicates and helpers
      static bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C);
      static bool isFreeLike(const CallEvent &Call, CheckerContext &C);

      static const CleanupSpec* getCleanupSpec(const CallEvent &Call, CheckerContext &C);

      const FieldDecl* resolveFieldDeclFromObjectParam(const Expr *ObjExpr,
                                                       StringRef FieldName,
                                                       CheckerContext &C) const;

      void recordManualFreeOfField(const MemRegion *BaseObjReg,
                                   const FieldDecl *FD,
                                   CheckerContext &C) const;

      void reportDoubleFree(const CallEvent &Call, StringRef FieldName,
                            StringRef HelperName, CheckerContext &C) const;
};

bool SAGenTestChecker::isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (Origin && ExprHasName(Origin, Name, C))
    return true;
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  return false;
}

bool SAGenTestChecker::isFreeLike(const CallEvent &Call, CheckerContext &C) {
  static const char *FreeFuncs[] = {"kfree", "kvfree", "kfree_sensitive", "vfree"};
  for (const char *F : FreeFuncs) {
    if (isCallNamed(Call, F, C))
      return true;
  }
  return false;
}

const CleanupSpec* SAGenTestChecker::getCleanupSpec(const CallEvent &Call, CheckerContext &C) {
  for (const auto &Entry : CleanupTable) {
    if (isCallNamed(Call, Entry.FuncName, C))
      return &Entry;
  }
  return nullptr;
}

const FieldDecl* SAGenTestChecker::resolveFieldDeclFromObjectParam(const Expr *ObjExpr,
                                                                   StringRef FieldName,
                                                                   CheckerContext &C) const {
  if (!ObjExpr)
    return nullptr;

  QualType QT = ObjExpr->getType();
  if (QT.isNull())
    return nullptr;

  QualType PointeeOrSelf = QT->isPointerType() ? QT->getPointeeType() : QT;
  if (PointeeOrSelf.isNull())
    return nullptr;

  const RecordType *RT = PointeeOrSelf->getAs<RecordType>();
  if (!RT)
    return nullptr;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return nullptr;

  for (const FieldDecl *FD : RD->fields()) {
    if (FD && FD->getName().equals(FieldName))
      return FD;
  }
  return nullptr;
}

void SAGenTestChecker::recordManualFreeOfField(const MemRegion *BaseObjReg,
                                               const FieldDecl *FD,
                                               CheckerContext &C) const {
  if (!BaseObjReg || !FD)
    return;

  ProgramStateRef State = C.getState();

  // Get existing set of freed fields for this object, or an empty set.
  FreedFieldSetTy Set;
  if (const FreedFieldSetTy *Existing = State->get<ManualFreedMap>(BaseObjReg))
    Set = *Existing;
  else
    Set = State->get_context<FreedFieldSet>().getEmptySet();

  // Add the field to the set.
  FreedFieldSetTy NewSet = State->get_context<FreedFieldSet>().add(Set, FD);
  if (NewSet != Set) {
    State = State->set<ManualFreedMap>(BaseObjReg, NewSet);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call, StringRef FieldName,
                                        StringRef HelperName, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
  Msg += "Double free: field '";
  Msg += FieldName;
  Msg += "' freed manually and again by '";
  Msg += HelperName;
  Msg += "'";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg.str(), N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // 1) Handle manual frees like kfree(obj->member);
  if (isFreeLike(Call, C)) {
    if (Call.getNumArgs() >= 1) {
      const Expr *Arg0 = Call.getArgExpr(0);
      if (Arg0) {
        // Find the MemberExpr inside the argument expression.
        const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(Arg0);
        if (ME) {
          const ValueDecl *VD = ME->getMemberDecl();
          const FieldDecl *FD = dyn_cast_or_null<FieldDecl>(VD);
          if (FD) {
            const Expr *BaseE = ME->getBase();
            if (BaseE) {
              const MemRegion *BaseObjReg = getMemRegionFromExpr(BaseE, C);
              if (BaseObjReg) {
                BaseObjReg = BaseObjReg->getBaseRegion();
                if (BaseObjReg) {
                  recordManualFreeOfField(BaseObjReg, FD, C);
                }
              }
            }
          }
        }
      }
    }
    return;
  }

  // 2) Handle composite cleanup helpers, e.g. bch2_dev_buckets_free(obj);
  if (const CleanupSpec *Spec = getCleanupSpec(Call, C)) {
    if (Call.getNumArgs() > Spec->ObjParamIndex) {
      const Expr *ObjE = Call.getArgExpr(Spec->ObjParamIndex);
      if (!ObjE)
        return;

      const MemRegion *BaseObjReg = getMemRegionFromExpr(ObjE, C);
      if (!BaseObjReg)
        return;
      BaseObjReg = BaseObjReg->getBaseRegion();
      if (!BaseObjReg)
        return;

      const FreedFieldSetTy *FreedSet = State->get<ManualFreedMap>(BaseObjReg);

      for (const char *FieldName : Spec->FreedFields) {
        const FieldDecl *FD = resolveFieldDeclFromObjectParam(ObjE, FieldName, C);
        if (!FD)
          continue;

        if (FreedSet && FreedSet->contains(FD)) {
          reportDoubleFree(Call, FieldName, Spec->FuncName, C);
          // Do not early return; continue to check other fields if any.
        }
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects manual free of struct member followed by a cleanup helper freeing the same member (double free).",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 135 |   FreedFieldSetTy Set;

	- Error Messages: no matching function for call to ‘llvm::ImmutableSet<const clang::FieldDecl*>::ImmutableSet()’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
