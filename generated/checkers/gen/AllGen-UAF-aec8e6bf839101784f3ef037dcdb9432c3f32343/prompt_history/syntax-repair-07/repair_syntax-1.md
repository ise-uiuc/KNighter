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
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state set to record released member pointer regions (FieldRegion).
REGISTER_SET_WITH_PROGRAMSTATE(ReleasedMembers, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::BranchCondition,
    check::Bind
  > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use-after-free/double-release", "Memory Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:
      // Helpers
      static bool callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C);
      static bool isReleaseLikeFunction(const CallEvent &Call, CheckerContext &C);
      static bool isKnownObjectMemberReleaser(const CallEvent &Call,
                                              SmallVectorImpl<StringRef> &ReleasedFields,
                                              CheckerContext &C);

      static const FieldRegion *stripToFieldRegion(const MemRegion *R);
      static const FieldRegion *getFieldRegionFromExpr(const Expr *E, CheckerContext &C);
      static const FieldRegion *getFieldRegionFromObjectAndName(const Expr *ObjArg,
                                                                StringRef FieldName,
                                                                CheckerContext &C);
      static bool isNullSVal(SVal V);

      void report(CheckerContext &C, const Stmt *S, StringRef Msg) const;
};

bool SAGenTestChecker::callHasName(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, Name, C);
}

bool SAGenTestChecker::isReleaseLikeFunction(const CallEvent &Call, CheckerContext &C) {
  // Exact matches for known release/put/free functions
  static const char *Exact[] = {
    "fput", "kfree", "kvfree", "filp_close", "blkdev_put", "bio_put", "sock_release", "put_device"
  };
  for (const char *N : Exact) {
    if (callHasName(Call, N, C))
      return true;
  }

  // Conservative heuristic: names that contain "free" or end with "put".
  // To avoid noise, only accept if first arg syntactically looks like a member (MemberExpr).
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  // Extract callee source text and apply heuristic
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(OE->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  bool NameLooksRelease = Text.contains_lower("free(") || Text.endswith_lower("put)") || Text.contains_lower("put(");
  if (!NameLooksRelease)
    return false;

  if (Call.getNumArgs() > 0) {
    if (const Expr *A0 = Call.getArgExpr(0)) {
      const Expr *IE = A0->IgnoreParenImpCasts();
      if (isa<MemberExpr>(IE))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isKnownObjectMemberReleaser(const CallEvent &Call,
                                                   SmallVectorImpl<StringRef> &ReleasedFields,
                                                   CheckerContext &C) {
  // For our target bug, btrfs_close_bdev(device) releases device->bdev_file
  if (callHasName(Call, "btrfs_close_bdev", C)) {
    ReleasedFields.push_back("bdev_file");
    return true;
  }
  return false;
}

const FieldRegion *SAGenTestChecker::stripToFieldRegion(const MemRegion *R) {
  if (!R)
    return nullptr;

  const MemRegion *Cur = R;
  // Walk up through subregions until we find a FieldRegion
  while (Cur) {
    if (const auto *FR = dyn_cast<FieldRegion>(Cur))
      return FR;
    if (const auto *SR = dyn_cast<SubRegion>(Cur)) {
      Cur = SR->getSuperRegion();
      continue;
    }
    break;
  }
  return nullptr;
}

const FieldRegion *SAGenTestChecker::getFieldRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  // Do not IgnoreImplicit before calling getMemRegionFromExpr (per suggestion)
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;

  // Always fetch base region as per suggestion (not used for FR extraction but to respect guideline)
  (void)MR->getBaseRegion();

  // Try to find a FieldRegion by going up the region chain
  return stripToFieldRegion(MR);
}

const FieldRegion *SAGenTestChecker::getFieldRegionFromObjectAndName(const Expr *ObjArg,
                                                                     StringRef FieldName,
                                                                     CheckerContext &C) {
  if (!ObjArg)
    return nullptr;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // Acquire the value of the object pointer
  SVal ObjV = State->getSVal(ObjArg, LCtx);
  const MemRegion *ObjReg = ObjV.getAsRegion();

  // If we couldn't get a region, try to create a symbolic region from a symbol
  if (!ObjReg) {
    if (SymbolRef Sym = ObjV.getAsSymbol()) {
      MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
      ObjReg = MRMgr.getSymbolicRegion(Sym);
    }
  }
  if (!ObjReg)
    return nullptr;

  // We need the pointee type's record to find the field decl
  QualType ObjTy = ObjArg->getType();
  if (ObjTy.isNull())
    return nullptr;
  QualType Pointee = ObjTy->getPointeeType();
  if (Pointee.isNull())
    return nullptr;

  const RecordType *RT = Pointee->getAs<RecordType>();
  if (!RT)
    return nullptr;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return nullptr;

  const FieldDecl *TargetFD = nullptr;
  for (const FieldDecl *FD : RD->fields()) {
    if (FD->getName() == FieldName) {
      TargetFD = FD;
      break;
    }
  }
  if (!TargetFD)
    return nullptr;

  // Create a FieldRegion on top of the (symbolic) object region
  const SubRegion *Super = dyn_cast<SubRegion>(ObjReg);
  if (!Super) {
    // If ObjReg is not a subregion, wrap it into a symbolic region (fallback)
    if (const auto *BR = dyn_cast<MemSpaceRegion>(ObjReg)) {
      (void)BR; // unlikely
      return nullptr;
    }
    // Try creating a symbolic super region if possible using the region's symbol
    // Otherwise, we cannot safely construct the field region.
    return nullptr;
  }

  MemRegionManager &MRMgr = C.getSValBuilder().getRegionManager();
  const FieldRegion *FR = MRMgr.getFieldRegion(TargetFD, Super);
  return FR;
}

bool SAGenTestChecker::isNullSVal(SVal V) {
  if (auto DV = V.getAs<DefinedSVal>()) {
    if (auto CI = DV->getAs<nonloc::ConcreteInt>())
      return CI->getValue().isNullValue();
    if (auto LCI = DV->getAs<loc::ConcreteInt>())
      return LCI->getValue().isZero();
  }
  return false;
}

void SAGenTestChecker::report(CheckerContext &C, const Stmt *S, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

// PostCall: mark member pointers that are released, and model known releasers.
void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Case A: Direct release/free/put-like calls on a member pointer argument.
  if (isReleaseLikeFunction(Call, C)) {
    if (Call.getNumArgs() > 0) {
      if (const Expr *ArgE = Call.getArgExpr(0)) {
        const FieldRegion *FR = getFieldRegionFromExpr(ArgE, C);
        if (FR) {
          State = State->add<ReleasedMembers>(FR);
          C.addTransition(State);
          return;
        }
      }
    }
  }

  // Case B: Known object-member releasers, e.g., btrfs_close_bdev(device) releases device->bdev_file
  SmallVector<StringRef, 2> ReleasedFields;
  if (isKnownObjectMemberReleaser(Call, ReleasedFields, C)) {
    if (Call.getNumArgs() > 0) {
      const Expr *ObjE = Call.getArgExpr(0);
      for (StringRef FName : ReleasedFields) {
        const FieldRegion *FR = getFieldRegionFromObjectAndName(ObjE, FName, C);
        if (FR) {
          State = State->add<ReleasedMembers>(FR);
        }
      }
      C.addTransition(State);
    }
  }
}

// PreCall: detect double release and use-after-free via known deref functions.
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Double-release: calling release-like function again on the same member pointer
  if (isReleaseLikeFunction(Call, C)) {
    if (Call.getNumArgs() > 0) {
      if (const Expr *ArgE = Call.getArgExpr(0)) {
        const FieldRegion *FR = getFieldRegionFromExpr(ArgE, C);
        if (FR && State->contains<ReleasedMembers>(FR)) {
          report(C, Call.getOriginExpr(), "Double release of a member pointer; set it to NULL after releasing.");
          return;
        }
      }
    }
  }

  // UAF via passing to a function that dereferences given params
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (functionKnownToDeref(Call, DerefParams)) {
    for (unsigned Idx : DerefParams) {
      if (Idx >= Call.getNumArgs())
        continue;
      const Expr *ArgE = Call.getArgExpr(Idx);
      const FieldRegion *FR = getFieldRegionFromExpr(ArgE, C);
      if (FR && State->contains<ReleasedMembers>(FR)) {
        report(C, Call.getOriginExpr(), "Use-after-free: released member pointer passed to a function that dereferences it.");
        return;
      }
    }
  }
}

// Detect "if (obj->member)" or similar null checks on already released member pointers.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  // Try to find a MemberExpr in the condition
  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(CondE);
  if (!ME) {
    C.addTransition(State);
    return;
  }

  const FieldRegion *FR = getFieldRegionFromExpr(ME, C);
  if (FR && State->contains<ReleasedMembers>(FR)) {
    report(C, Condition, "Dangling member pointer used in condition after release.");
    return;
  }

  C.addTransition(State);
}

// Clear released state when the field is set to NULL (the fix pattern), or overwritten.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LReg = Loc.getAsRegion();
  if (!LReg) {
    C.addTransition(State);
    return;
  }

  // Always get base region per guideline
  (void)LReg->getBaseRegion();

  const FieldRegion *FR = stripToFieldRegion(LReg);
  if (!FR) {
    C.addTransition(State);
    return;
  }

  if (State->contains<ReleasedMembers>(FR)) {
    // If assigned NULL => clear. If overwritten with something else => also clear.
    State = State->remove<ReleasedMembers>(FR);
    C.addTransition(State);
    return;
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free/double-release when a released member pointer is not cleared to NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 91 |   bool NameLooksRelease = Text.contains_lower("free(") || Text.endswith_lower("put)") || Text.contains_lower("put(");

	- Error Messages: ‘class llvm::StringRef’ has no member named ‘contains_lower’

- Error Line: 91 |   bool NameLooksRelease = Text.contains_lower("free(") || Text.endswith_lower("put)") || Text.contains_lower("put(");

	- Error Messages: ‘class llvm::StringRef’ has no member named ‘endswith_lower’

- Error Line: 91 |   bool NameLooksRelease = Text.contains_lower("free(") || Text.endswith_lower("put)") || Text.contains_lower("put(");

	- Error Messages: ‘class llvm::StringRef’ has no member named ‘contains_lower’

- Error Line: 219 |       return CI->getValue().isNullValue();

	- Error Messages: ‘const class llvm::APSInt’ has no member named ‘isNullValue’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
