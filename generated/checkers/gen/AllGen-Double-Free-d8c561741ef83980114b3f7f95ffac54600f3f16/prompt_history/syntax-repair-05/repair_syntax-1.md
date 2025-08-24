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
#include "llvm/ADT/StringRef.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// ------------ Program state ------------

struct ResourceInfo {
  unsigned Step;                // 0 = none, 1 = HW created
  const char *ExpectedDestroy;  // expected HW-only destroy function name (literal)
  bool IsParamOwned;            // resource is owned by caller (argument/parameter)
  ResourceInfo() : Step(0), ExpectedDestroy(nullptr), IsParamOwned(false) {}
  ResourceInfo(unsigned S, const char *ED, bool P)
      : Step(S), ExpectedDestroy(ED), IsParamOwned(P) {}
};

REGISTER_MAP_WITH_PROGRAMSTATE(ResourceInfoMap, const MemRegion*, ResourceInfo)

// ------------ Helper tables ------------

struct CreateDestroyPair {
  const char *CreateName;
  const char *DestroyName;
  unsigned ResourceArgIndex; // index of resource arg in create call
};

// We cover both the low-level core create and the wrapper create helper.
static const CreateDestroyPair KnownPairs[] = {
  // mlx5_core_create_sq(dev, in, inlen, &sq->sqn)
  { "mlx5_core_create_sq", "mlx5_core_destroy_sq", 3 },
  // hws_send_ring_create_sq(mdev, pdn, sqc_data, queue, sq, cq)
  { "hws_send_ring_create_sq", "mlx5_core_destroy_sq", 4 }
};

// ------------ Utility helpers ------------

static bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, Name, C);
}

static bool isDestroyName(const CallEvent &Call, const char *Expected, CheckerContext &C) {
  if (!Expected)
    return false;
  return isCallNamed(Call, Expected, C);
}

static bool isOverScopedCleanupName(const CallEvent &Call, CheckerContext &C) {
  // Prefer Identifier if present, fallback to source-based contains check.
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    std::string L = ID->getName().lower();
    return (L.find("close") != std::string::npos) ||
           (L.find("free") != std::string::npos) ||
           (L.find("release") != std::string::npos);
  }
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  return ExprHasName(OE, "close", C) || ExprHasName(OE, "free", C) ||
         ExprHasName(OE, "release", C);
}

static bool isParamRegion(const MemRegion *R) {
  if (!R)
    return false;
  const MemRegion *Base = R->getBaseRegion();
  return Base && isa<ParmVarRegion>(Base);
}

// Extracts the resource base region from a creation call argument.
// Handles patterns like: &sq->sqn  -> returns region of 'sq' base
//                        sq        -> returns region of 'sq'
static const MemRegion *getResourceRegionFromCreateArg(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  // Address-of member, e.g., &sq->sqn
  if (const auto *UO = dyn_cast<UnaryOperator>(E->IgnoreParenCasts())) {
    if (UO->getOpcode() == UO_AddrOf) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (const auto *ME = dyn_cast<MemberExpr>(Sub)) {
        const Expr *BaseE = ME->getBase();
        if (BaseE) {
          if (const MemRegion *R = getMemRegionFromExpr(BaseE, C)) {
            return R->getBaseRegion();
          }
        }
      }
      // &Var (fallback)
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (const MemRegion *R = getMemRegionFromExpr(DRE, C)) {
          return R->getBaseRegion();
        }
      }
    }
  }

  // Generic: sq (pointer/resource variable)
  if (const MemRegion *R = getMemRegionFromExpr(E, C)) {
    return R->getBaseRegion();
  }
  return nullptr;
}

// Heuristic: only warn inside functions that look like create/open helpers.
static bool isCreationLikeFunction(CheckerContext &C) {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;
  const Decl *D = LCtx->getDecl();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;
  std::string Name = FD->getNameAsString();
  for (auto &ch : Name) ch = std::tolower(ch);
  return Name.find("create") != std::string::npos ||
         Name.find("open") != std::string::npos;
}

// ------------ Checker ------------

class SAGenTestChecker : public Checker<
                           check::PostCall,
                           check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(new BugType(this, "Over-scoped cleanup in error path", "Resource Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void maybeRecordCreate(const CallEvent &Call, CheckerContext &C) const;
  void maybeReportOverScoped(const CallEvent &Call,
                             const MemRegion *ResReg,
                             const ResourceInfo &Info,
                             CheckerContext &C) const;
};

void SAGenTestChecker::maybeRecordCreate(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (const auto &Pair : KnownPairs) {
    if (!isCallNamed(Call, Pair.CreateName, C))
      continue;

    if (Pair.ResourceArgIndex >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Pair.ResourceArgIndex);
    if (!ArgE)
      continue;

    const MemRegion *ResReg = getResourceRegionFromCreateArg(ArgE, C);
    if (!ResReg)
      continue;

    bool ParamOwned = isParamRegion(ResReg);
    ResourceInfo Info(/*Step=*/1, /*ExpectedDestroy=*/Pair.DestroyName, /*IsParamOwned=*/ParamOwned);

    State = State->set<ResourceInfoMap>(ResReg, Info);
    C.addTransition(State);
    return; // only one match per call
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Record resource creation steps from known create functions.
  maybeRecordCreate(Call, C);
}

void SAGenTestChecker::maybeReportOverScoped(const CallEvent &Call,
                                             const MemRegion *ResReg,
                                             const ResourceInfo &Info,
                                             CheckerContext &C) const {
  if (!BT || !ResReg)
    return;

  // Heuristic narrowing: only warn in create/open-like functions.
  if (!isCreationLikeFunction(C))
    return;

  // Only warn if the resource belongs to a parameter (owned by the caller).
  if (!Info.IsParamOwned)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Over-scoped cleanup: call HW destroy instead of close/free to avoid double free", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // For each argument, see if it refers to a tracked resource.
  for (unsigned i = 0, e = Call.getNumArgs(); i != e; ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    const MemRegion *ArgReg = getMemRegionFromExpr(ArgE, C);
    if (!ArgReg)
      continue;
    ArgReg = ArgReg->getBaseRegion();

    // Look up resource info for this region.
    const ResourceInfo *Info = State->get<ResourceInfoMap>(ArgReg);
    if (!Info || Info->Step != 1)
      continue;

    // If this is the correct HW destroy, clear the state and accept it.
    if (isDestroyName(Call, Info->ExpectedDestroy, C)) {
      State = State->remove<ResourceInfoMap>(ArgReg);
      C.addTransition(State);
      continue;
    }

    // If this looks like an over-scoped cleanup (close/free/release), report.
    if (isOverScopedCleanupName(Call, C)) {
      maybeReportOverScoped(Call, ArgReg, *Info, C);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects over-scoped cleanup in error paths (use HW destroy instead of close/free to avoid double free)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

## Error Messages

- Error Line: 42 |   struct ProgramStateTrait<Name> : public ProgramStatePartialTrait<Name##Ty> { \

	- Error Messages: specialization of ‘template<class T> struct clang::ento::ProgramStateTrait’ in different namespace [-fpermissive]

- Error Line: 42 |   struct ProgramStateTrait<Name> : public ProgramStatePartialTrait<Name##Ty> { \

	- Error Messages: xplicit specialization of ‘template<class T> struct clang::ento::ProgramStateTrait’ outside its namespace must use a nested-name-specifier [-fpermissive]

- Error Line: 43 |     static void *GDMIndex() {                                                  \

	- Error Messages: definition of ‘static void* clang::ento::ProgramStateTrait<{anonymous}::{anonymous}::ResourceInfoMap>::GDMIndex()’ is not in namespace enclosing ‘clang::ento::ProgramStateTrait<{anonymous}::{anonymous}::ResourceInfoMap>’ [-fpermissive]

- Error Line: 90 |   return Base && isa<ParmVarRegion>(Base);

	- Error Messages: ‘ParmVarRegion’ was not declared in this scope

- Error Line: 90 |   return Base && isa<ParmVarRegion>(Base);

	- Error Messages: no matching function for call to ‘isa<<expression error> >(const clang::ento::MemRegion*&)’

- Error Line: 90 |   return Base && isa<ParmVarRegion>(Base);

	- Error Messages: template argument 1 is invalid

- Error Line: 90 |   return Base && isa<ParmVarRegion>(Base);

	- Error Messages: template argument 1 is invalid

- Error Line: 234 |     X.Profile(ID);

	- Error Messages: ‘const struct {anonymous}::ResourceInfo’ has no member named ‘Profile’

- Error Line: 370 |       { return __x == __y; }

	- Error Messages: no match for ‘operator==’ (operand types are ‘const {anonymous}::ResourceInfo’ and ‘const {anonymous}::ResourceInfo’)

- Error Line: 362 |   operator==(const error_code& __lhs, const error_code& __rhs) noexcept

	- Error Messages: 362:3: note: candidate: ‘bool std::operator==(const std::error_code&, const std::error_code&)’

- Error Line: 362 |   operator==(const error_code& __lhs, const error_code& __rhs) noexcept

	- Error Messages: 362:32: note:   no known conversion for argument 1 from ‘const {anonymous}::ResourceInfo’ to ‘const std::error_code&’

- Error Line: 368 |   operator==(const error_code& __lhs, const error_condition& __rhs) noexcept

	- Error Messages: 368:3: note: candidate: ‘bool std::operator==(const std::error_code&, const std::error_condition&)’

- Error Line: 368 |   operator==(const error_code& __lhs, const error_condition& __rhs) noexcept

	- Error Messages: 368:32: note:   no known conversion for argument 1 from ‘const {anonymous}::ResourceInfo’ to ‘const std::error_code&’

- Error Line: 376 |   operator==(const error_condition& __lhs,

	- Error Messages: 376:3: note: candidate: ‘bool std::operator==(const std::error_condition&, const std::error_condition&)’

- Error Line: 376 |   operator==(const error_condition& __lhs,

	- Error Messages: 376:37: note:   no known conversion for argument 1 from ‘const {anonymous}::ResourceInfo’ to ‘const std::error_condition&’

- Error Line: 408 |   operator==(const error_condition& __lhs, const error_code& __rhs) noexcept

	- Error Messages: 408:3: note: candidate: ‘bool std::operator==(const std::error_condition&, const std::error_code&)’

- Error Line: 408 |   operator==(const error_condition& __lhs, const error_code& __rhs) noexcept

	- Error Messages: 408:37: note:   no known conversion for argument 1 from ‘const {anonymous}::ResourceInfo’ to ‘const std::error_condition&’



## Formatting

Your response should be like:

```cpp
{{whole fixed checker code here}}
```

Note, please return the **whole** checker code after fixing the compilation error.
