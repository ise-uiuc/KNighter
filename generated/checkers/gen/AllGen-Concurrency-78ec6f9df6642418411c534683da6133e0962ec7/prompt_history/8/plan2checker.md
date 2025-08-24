# Instruction

You are proficient in writing Clang Static Analyzer checkers.

Please help me write a CSA checker to detect a specific bug pattern.
You can refer to the `Target Bug Pattern` and `Target Patch` sections to help you understand the bug pattern.
Please make sure your checker can detect the bug shown in the `Buggy Code` section.
Please refer to the `Plan` section to implement the checker.
You can use the functions in `Utility Functions` section to help you write the checker.

The version of the Clang environment is Clang-18. You should consider the API compatibility.
The checker you write just needs to be able to detect the bug in C language, no need to consider C++ and Objective-C.

Please complete the template in `Checker Template` section. You should complete the content wrapped in `{{...}}`.

**Please read `Suggestions` section before writing the checker!**

# Utility Functions

```cpp
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

// Going downward in an AST tree, and find the Stmt of a secific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

// The expression should be the DeclRefExpr of the array
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

/// \brief Determines if the given call is to a function known to dereference
///        certain pointer parameters.
///
/// This function looks up the call's callee name in a known table of functions
/// that definitely dereference one or more of their pointer parameters. If the
/// function is found, it appends the 0-based parameter indices that are dereferenced
/// into \p DerefParams and returns \c true. Otherwise, it returns \c false.
///
/// \param[in] Call        The function call to examine.
/// \param[out] DerefParams
///     A list of parameter indices that the function is known to dereference.
///
/// \return \c true if the function is found in the known-dereference table,
///         \c false otherwise.
bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        // We found the function in our table, copy its param indices
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}

/// \brief Determines if the source text of an expression contains a specified name.
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  // Use const reference since getSourceManager() returns a const SourceManager.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  // Retrieve the source text corresponding to the expression.
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the extracted text contains the specified name.
  return ExprText.contains(Name);
}
```

# Clang Check Functions

```cpp
void checkPreStmt (const ReturnStmt *DS, CheckerContext &C) const
 // Pre-visit the Statement.

void checkPostStmt (const DeclStmt *DS, CheckerContext &C) const
 // Post-visit the Statement.

void checkPreCall (const CallEvent &Call, CheckerContext &C) const
 // Pre-visit an abstract "call" event.

void checkPostCall (const CallEvent &Call, CheckerContext &C) const
 // Post-visit an abstract "call" event.

void checkBranchCondition (const Stmt *Condition, CheckerContext &Ctx) const
 // Pre-visit of the condition statement of a branch (such as IfStmt).


void checkLocation (SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &) const
 // Called on a load from and a store to a location.

void checkBind (SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const
 // Called on binding of a value to a location.


void checkBeginFunction (CheckerContext &Ctx) const
 // Called when the analyzer core starts analyzing a function, regardless of whether it is analyzed at the top level or is inlined.

void checkEndFunction (const ReturnStmt *RS, CheckerContext &Ctx) const
 // Called when the analyzer core reaches the end of a function being analyzed regardless of whether it is analyzed at the top level or is inlined.

void checkEndAnalysis (ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
 // Called after all the paths in the ExplodedGraph reach end of path.


bool evalCall (const CallEvent &Call, CheckerContext &C) const
 // Evaluates function call.

ProgramStateRef evalAssume (ProgramStateRef State, SVal Cond, bool Assumption) const
 // Handles assumptions on symbolic values.

ProgramStateRef checkRegionChanges (ProgramStateRef State, const InvalidatedSymbols *Invalidated, ArrayRef< const MemRegion * > ExplicitRegions, ArrayRef< const MemRegion * > Regions, const LocationContext *LCtx, const CallEvent *Call) const
 // Called when the contents of one or more regions change.

void checkASTDecl (const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration in the AST.

void checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration that has a statement body in the AST.
```


# Suggestions

- Always perform a NULL check after retrieving a pointer type.

- When you are going to track the return value of a function, if the type of the return value is a pointer (e.g. `int*`), you should use `MemRegion*` to mark it. If the type is a basic type (e.g. `int`), you should use `SymbolRef`.

- Use `generateNonFatalErrorNode()` rather than `generateErrorNode()` to report all possible bugs in a file.

- When you are going to infer the maximal value, invoke `inferSymbolMaxVal()` to help you. For example, when infering the maximal value of `a*b`, invoke `inferSymbolMaxVal()` twice to infer the maximal values of `a` and `b`, and multiply the values to infer the final maximal value.

- If you are not sure whether there is a bug or not because of missing information (e.g. undecidable array size), DO NOT report it as potential bug.

- **Always** invoke `getBaseRegion()` to get the base region of a memory region. For example, after the statement "const MemRegion *BaseReg = Loc.getAsRegion();", you should perform "BaseReg = BaseReg->getBaseRegion();".

- Do not perform `IgnoreImplicit()` before invoking the function `getMemRegionFromExpr()`, and you must perform `getBaseRegion()` after this function.

- For pointer analysis, please use a program state (like `REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)`) and `checkBind` to track the aliasing information.

- DO NOT use placeholder logic in the checker. Always implement the logic in the checker.

- Use `std::make_unique<PathSensitiveBugReport>` or `std::make_unique<BasicBugReport>` to create a bug report. Note, the error message should be **short** and clear.

- When verifying a function call's name, use the utility function ExprHasName() for accurate checking.
  - Bad example: `const IdentifierInfo *Callee = Call.getCalleeIdentifier(); if (!Callee || Callee->getName() != "check_add_overflow") return;`
  - Good example: `const Expr *OriginExpr = Call.getOriginExpr(); if (!OriginExpr || !ExprHasName(OriginExpr, "check_add_overflow", C)) return;`
  - For other checking like type checking, use its corresponding Clang API, like `C.getASTContext().getTypeSize(Ty)`

- Please follow the plan!!


# Examples

## Example 1
### Bug Pattern

The bug pattern in the provided patch is the use of `devm_kcalloc()` for allocating memory, which results in automatic memory management by the device-managed allocation API. This can lead to a double free issue when manual deallocation is also performed with functions like `pinctrl_utils_free_map()`. The root cause is combining automatic device-managed memory allocation with manual memory deallocation, which can result in freeing memory twice and cause undefined behavior


### Plan

1. **Declare a Taint Tag:**
   - Use a unique identifier (e.g., `static TaintTagType TaintTag = 101;`) to mark allocations from `devm_*` functions.

2. **Model the Memory Allocation (evalCall):**
   - In the `evalCall` method, intercept calls to `devm_kcalloc`, `devm_kmalloc`, etc.
   - Create a symbolic region to represent the newly allocated memory using `getConjuredHeapSymbolVal`.
   - Bind this symbolic region to the return expression of the call.

3. **Taint the Return Value (checkPostCall):**
   - In the `checkPostCall` callback, if the callee is `devm_*`, retrieve the return value’s symbol and mark it as tainted (using `addTaint(State, retSymbol, TaintTag)`).

4. **Check Before Freeing (checkPreCall):**
   - Intercept calls to `kfree`, `kvfree`, and `pinctrl_utils_free_map`.
   - Extract the pointer argument’s symbol.
   - If the symbol is tainted, it indicates that this pointer originates from a `devm_*` allocation. Hence, report a potential double-free.

5. **Report Bugs (reportDoubleFree):**
   - Generate an error node using `generateNonFatalErrorNode`.
   - Create a `PathSensitiveBugReport` for the user, describing the “Double free of devm_* allocated memory.”


### Checker Code
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


using namespace clang;
using namespace ento;
using namespace taint;

// Define a unique taint tag for devm_ allocations.
static TaintTagType TaintTag = 101;

namespace {

class SAGenTestChecker
  : public Checker<eval::Call,      // For modeling certain functions
                   check::PreCall,  // For checking pre-call conditions
                   check::PostCall> // For checking post-call conditions
{
  mutable std::unique_ptr<BugType> BT;

public:
  // Constructor to initialize the BugType describing our double-free bug.
  SAGenTestChecker()
      : BT(new BugType(this, "Double Free of devm Allocated Memory",
                       "Memory Management")) {}

  // This callback can be used to model the behavior of functions, including
  // allocating memory or mutating states in a custom way.
  bool evalCall(const CallEvent &Call, CheckerContext &C) const;

  // Post-call check: track when devm_* allocation functions return memory,
  // marking the returned pointer as "tainted" (i.e., devm-allocated).
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  // Pre-call check: if the function is a known free function (kfree, kvfree, or
  // pinctrl_utils_free_map), verify if the passed pointer was previously
  // devm-allocated. If so, report a double-free issue.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C,
                        const MemRegion *Region) const;
};

} // end anonymous namespace

/// evalCall - Used to model certain function calls manually. Here, we intercept
/// certain devm_* allocations to simulate a symbolic region allocation.
bool SAGenTestChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return false;

  // If the function name matches any of the devm_* memory allocation functions,
  // create a symbolic region to represent the newly allocated memory.
  if (Callee->getName() == "devm_kcalloc" ||
      Callee->getName() == "devm_kmalloc" ||
      Callee->getName() == "devm_kzalloc" ||
      Callee->getName() == "devm_kmalloc_array") {

    // Retrieve the original call expression.
    const Expr *expr = Call.getOriginExpr();
    if (!expr)
      return false;

    const CallExpr *CE = dyn_cast<CallExpr>(expr);
    if (!CE)
      return false;

    // Create a conjured symbol representing the allocated memory. This
    // effectively simulates an allocation site for the static analyzer.
    unsigned Count = C.blockCount();
    SValBuilder &svalBuilder = C.getSValBuilder();
    const LocationContext *LCtx = C.getPredecessor()->getLocationContext();
    DefinedSVal RetVal =
        svalBuilder.getConjuredHeapSymbolVal(CE, LCtx, Count).castAs<DefinedSVal>();

    // Initialize the symbolic memory with an undefined value. This is optional
    // but often done in the analyzer to track data flows.
    State = State->bindDefaultInitial(RetVal, UndefinedVal(), LCtx);

    // Bind the symbolic allocation to the call expression's return value.
    State = State->BindExpr(CE, C.getLocationContext(), RetVal);

    // If the return value is not a location, do not continue.
    if (!RetVal.getAs<Loc>())
      return false;

    // Finally, add the new state transition to the analyzer.
    if (State)
      C.addTransition(State);
  }

  // This indicates whether the call produced a new or different state.
  bool isDifferent = C.isDifferent();
  return isDifferent;
}

/// checkPostCall - After the call is evaluated, we mark the returned pointer
/// as tainted if it comes from a devm_* allocation function.
void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  // If it's one of our target devm_* allocation functions, taint the result.
  if (Callee->getName() == "devm_kcalloc" ||
      Callee->getName() == "devm_kmalloc" ||
      Callee->getName() == "devm_kzalloc" ||
      Callee->getName() == "devm_kmalloc_array") {

    // Ensure we have a valid call expression.
    const CallExpr *CE = dyn_cast<CallExpr>(Call.getOriginExpr());
    if (!CE)
      return;

    // Retrieve the return value.
    SVal RetVal = Call.getReturnValue();
    SymbolRef retSymbol = RetVal.getAsSymbol();
    if (retSymbol) {
      // Mark the symbol as "tainted" with our custom TaintTag,
      // indicating devm allocation.
      State = addTaint(State, retSymbol, TaintTag);
    }
    // Save the new state.
    C.addTransition(State);
  }
}

/// checkPreCall - Before kfree, kvfree, or pinctrl_utils_free_map is called,
/// check if the pointer to be freed is tagged as devm-allocated. If so,
/// issue a double-free warning.
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  // Handle pinctrl_utils_free_map. Note that the pointer is passed as
  // the second argument (index 1).
  if (Callee->getName() == "pinctrl_utils_free_map") {
    SVal arg1 = Call.getArgSVal(1);
    SymbolRef argSymbol = arg1.getAsSymbol();

    if (argSymbol) {
      // If this symbol was tainted as devm-allocated, report a double-free.
      if (isTainted(State, argSymbol, TaintTag)) {
        reportDoubleFree(Call, C, arg1.getAsRegion());
      }
    }
  }

  // Handle kfree/kvfree. The pointer is the first argument (index 0).
  if (Callee->getName() == "kfree" || Callee->getName() == "kvfree") {
    SVal arg0 = Call.getArgSVal(0);
    SymbolRef argSymbol = arg0.getAsSymbol();

    if (argSymbol) {
      // If this symbol was tainted as devm-allocated, report a double-free.
      if (isTainted(State, argSymbol, TaintTag)) {
        reportDoubleFree(Call, C, arg0.getAsRegion());
      }
    }
  }
}

/// reportDoubleFree - Emit a warning if devm-allocated memory is freed using
/// a standard free function, indicating a possible double-free.
void SAGenTestChecker::reportDoubleFree(const CallEvent &Call,
                                        CheckerContext &C,
                                        const MemRegion *Region) const {
  if (!BT)
    return;

  // Generate a node in the exploded graph for this error.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  // Create and populate a bug report object.
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free of devm_* allocated memory", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of memory allocated by devm_* functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```

## Example 2
### Bug Pattern

The bug pattern is that the function `devm_kasprintf()` can return NULL if it fails to allocate memory. When the return value is not checked and is subsequently dereferenced, it can lead to a NULL pointer dereference. This pattern can cause the program to crash if it tries to use the pointer returned by `devm_kasprintf()` without ensuring it is non-NULL.


### Plan

1. **Create and Manage Program State Maps:**
   - Define two maps using `REGISTER_MAP_WITH_PROGRAMSTATE`:
     - A `PossibleNullPtrMap` that associates `MemRegion`s with a boolean indicating whether they have been NULL-checked (`true` if checked, `false` if unchecked).
     - A `PtrAliasMap` to track alias relationships. This is needed so that if one pointer is checked, its aliases are also marked as checked.

2. **Identify the Relevant Function (`devm_kasprintf`):**
   - Implement an internal helper function `isDevmKasprintf(const CallEvent &Call)`.
   - In `checkPostCall`, if the function is `devm_kasprintf`, mark the return region in `PossibleNullPtrMap` as unchecked (`false`), since it hasn't undergone a NULL check yet.

3. **Marking Pointers as Checked:**
   - Implement a helper function `setChecked(State, Region)` which marks a pointer (and its aliases) as checked in the `PossibleNullPtrMap`.
   - This function is used whenever the checker determines a pointer has been NULL-checked.

4. **Observing Conditions (BranchCondition):**
   - In `checkBranchCondition`, examine the condition:
     - If it looks like `if (!ptr)`, `if (ptr == NULL)`, `if (ptr != NULL)`, or just `if (ptr)`, determine the region being tested.
     - Once identified, call `setChecked(...)` on that region.

5. **Detecting Dereferences (Location):**
   - In `checkLocation`, catch any read/write operation (`*ptr`).
   - If the pointer has a mapping in `PossibleNullPtrMap` and it is still set to `false`, issue a warning (using `C.emitReport(...)`) because the pointer might be `NULL`-not-checked.

6. **Tracking Aliases (Bind):**
   - In `checkBind`, when a pointer is stored into another pointer (e.g., `p2 = p1;`), record this alias in `PtrAliasMap`.
   - When one pointer becomes checked, `setChecked(...)` will update the aliases as well.
   - Do not update the `PossibleNullPtrMap` in the `checkBind` function.


### Checker Code
```cpp
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
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;

// A program-state map from MemRegions to a boolean that tells whether
// that region has been "checked" for null (true) or is still unchecked (false).
REGISTER_MAP_WITH_PROGRAMSTATE(PossibleNullPtrMap, const MemRegion*, bool)
// Program state map to track pointer aliasing
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

//----------------------------------------------------------------------
// Helper: Is this devm_kasprintf?
//----------------------------------------------------------------------
static bool isDevmKasprintf(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    return ID->getName() == "devm_kasprintf";
  }
  return false;
}

ProgramStateRef setChecked(ProgramStateRef State, const MemRegion *MR) {
  const bool *Checked = State->get<PossibleNullPtrMap>(MR);
  if (Checked && *Checked == false) {
    State = State->set<PossibleNullPtrMap>(MR, true);
  }

  auto AliasReg = State->get<PtrAliasMap>(MR);
  if (AliasReg) { // Fix 1: Adjust type to pointer to const
      const bool *AliasChecked = State->get<PossibleNullPtrMap>(*AliasReg);
      if (AliasChecked && *AliasChecked == false) {
        State = State->set<PossibleNullPtrMap>(*AliasReg, true);
      }
  }
  return State;
}

//----------------------------------------------------------------------
// Main Checker Class
//----------------------------------------------------------------------
namespace {
class SAGenTestChecker
  : public Checker<
      check::PostCall,
      check::PreCall,
      check::BranchCondition,
      check::Location,
      check::Bind
    > {

  BugType BT; // We'll initialize in constructor

public:
  SAGenTestChecker()
    : BT(this, "Dereference before NULL check") {}

  // Checker callbacks
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
};
} // end anonymous namespace

//----------------------------------------------------------------------
// checkPostCall: Called after a function call is evaluated
//----------------------------------------------------------------------
void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If the call is devm_kasprintf, mark its return region as "unchecked" = false
  if (isDevmKasprintf(Call)) {
    const MemRegion *MR = Call.getReturnValue().getAsRegion(); // Fix 2: semicolon added
    if (!MR)
      return;

    State = State->set<PossibleNullPtrMap>(MR, false);
  }

  C.addTransition(State);
}

//----------------------------------------------------------------------
// checkPreCall: Called right before a function call is evaluated
//----------------------------------------------------------------------
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return; // not one of our "known to deref" functions

  ProgramStateRef State = C.getState();

  // For each parameter index known to be dereferenced
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    SVal ArgVal = Call.getArgSVal(Idx);
    if (const MemRegion *MR = ArgVal.getAsRegion()) {
      const MemRegion *BaseReg = MR->getBaseRegion();

      const bool *Checked = State->get<PossibleNullPtrMap>(BaseReg);
      if (Checked && *Checked == false) {
        // We found a pointer from devm_kasprintf that is about to be dereferenced
        // by a known-deref function, but it was never checked for NULL.
        ExplodedNode *N = C.generateErrorNode();
        if (!N)
          return;

        auto report = std::make_unique<PathSensitiveBugReport>(
            BT, "Passing devm_kasprintf pointer to a function that dereferences "
                "it without checking for NULL", N);
        // Optionally, you can add a range or more information
        C.emitReport(std::move(report));
      }
    }
  }
}

//----------------------------------------------------------------------
// checkBranchCondition: Called when evaluating an 'if (...)' or 'while(...)' condition
//----------------------------------------------------------------------
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    // Not an expression-based condition, just add a transition
    C.addTransition(State);
    return;
  }

  // Remove casts/parens
  CondE = CondE->IgnoreParenCasts();

  // 1) Look for "if (!ptr)"
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      SVal SubVal = State->getSVal(SubE, C.getLocationContext());
      if (const MemRegion *MR = SubVal.getAsRegion()) {
        if (const MemRegion *BaseReg = MR->getBaseRegion()) {
          // Mark pointer as "checked."
          State = setChecked(State, BaseReg);
        }
      }
    }
  }
  // 2) Look for "if (ptr == NULL)" or "if (ptr != NULL)"
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                 Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                 Expr::NPC_ValueDependentIsNull);
      // Identify which side is the pointer
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull) {
        PtrExpr = RHS;
      } else if (RHSIsNull && !LHSIsNull) {
        PtrExpr = LHS;
      }

      if (PtrExpr) {
        SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
        if (const MemRegion *MR = PtrVal.getAsRegion()) {
          if (const MemRegion *BaseReg = MR->getBaseRegion()) {
            // Mark as checked
            State = setChecked(State, BaseReg);
          }
        }
      }
    }
  }
  // 3) Look for "if (ptr)"
  else {
    SVal CondVal = State->getSVal(CondE, C.getLocationContext());
    if (const MemRegion *MR = CondVal.getAsRegion()) {
      if (const MemRegion *BaseReg = MR->getBaseRegion()) {
        // Mark pointer as "checked."
        State = setChecked(State, BaseReg);
      }
    }
  }

  C.addTransition(State);
}

//----------------------------------------------------------------------
// checkLocation: Called on explicit memory load/store (e.g. *ptr)
//----------------------------------------------------------------------
void SAGenTestChecker::checkLocation(SVal loc, bool isLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (const MemRegion *MR = loc.getAsRegion()) {
    if (const MemRegion *BaseReg = MR->getBaseRegion()) {
      const bool *Checked = State->get<PossibleNullPtrMap>(BaseReg);
      if (Checked && *Checked == false) {
        // We found a direct dereference of an unchecked pointer from devm_kasprintf
        ExplodedNode *N = C.generateErrorNode();
        if (!N)
          return;

        auto report = std::make_unique<PathSensitiveBugReport>(
            BT, "Dereference before checking for null (devm_kasprintf)", N);
        report->addRange(S->getSourceRange()); // highlight the statement
        C.emitReport(std::move(report));
      }
    }
  }
}

//----------------------------------------------------------------------
// checkBind: Called when a value is bound to a memory region
//----------------------------------------------------------------------
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Get the left-hand side region.
  if (const MemRegion *LHSReg = Loc.getAsRegion()) {
    // Get the right-hand side region (if any).
    LHSReg = LHSReg->getBaseRegion();
    if (!LHSReg)
      return;

    if (const MemRegion *MR = Val.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (!MR)
        return;

      State = State->set<PtrAliasMap>(LHSReg, MR);
      State = State->set<PtrAliasMap>(MR, LHSReg);
    }
  }
  C.addTransition(State);
}

//----------------------------------------------------------------------
// Registration
//----------------------------------------------------------------------
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereferences of pointers returned by devm_kasprintf without NULL checking",
      ""
  );
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```

## Example 3
### Bug Pattern

The bug pattern is using `kmalloc()` to allocate memory for a buffer that is later copied to user space without properly initializing the allocated memory. This can result in a kernel information leak if the allocated memory contains uninitialized or leftover data, which is then exposed to user space. The root cause is the lack of proper memory initialization after allocation, leading to potential exposure of sensitive kernel data. Using `kzalloc()` instead ensures that the allocated memory is zeroed out, preventing such information leaks.


### Plan

1. **Register Program State Map:**
   - Define two maps using `REGISTER_MAP_WITH_PROGRAMSTATE`:
      - Use `REGISTER_MAP_WITH_PROGRAMSTATE(UninitMemoryMap, const MemRegion *, bool)` to map memory regions to an initialization flag.
      - A `PtrAliasMap` to track alias relationships. This is needed so that if one pointer is checked, its aliases are also marked as checked.

2. **Track Memory Allocations (`checkPostCall`):**
   - **For `kmalloc`:**
     - Retrieve the call expression and its base `MemRegion`.
     - Mark the region as uninitialized (`true`).
   - **For `kzalloc`:**
     - Retrieve the call expression and its base `MemRegion`.
     - Mark the region as initialized (`false`).

3. **Detect Information Leak (`checkPreCall`):**
   - Identify calls to `copy_to_user`.
   - Retrieve the kernel source argument’s base `MemRegion`.
   - If the region is flagged as uninitialized in `UninitMemoryMap`, call `reportInfoLeak` to generate a warning.

4. **Bug Reporting (`reportInfoLeak`):**
   - Generate a non-fatal error node.
   - Emit a bug report with a message indicating potential kernel information leakage.


### Checker Code
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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to track uninitialized memory regions
REGISTER_MAP_WITH_PROGRAMSTATE(UninitMemoryMap, const MemRegion *, bool)
// Program state map to track pointer aliasing
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Location> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel Information Leak")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const;

   private:
      void reportInfoLeak(const MemRegion *MR, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  if (Callee->getName() == "kmalloc") {
    // Track kmalloc allocations, mark memory as uninitialized
    const Expr *expr = Call.getOriginExpr();
    if (!expr)
      return;

    const CallExpr *CE = dyn_cast<CallExpr>(expr);
    if (!CE)
      return;

    const MemRegion *MR = getMemRegionFromExpr(CE, C);
    if (!MR)
      return;

    MR = MR->getBaseRegion();
    if (!MR)
      return;
    State = State->set<UninitMemoryMap>(MR, true);
    C.addTransition(State);
  } else if (Callee->getName() == "kzalloc") {
    // Track kzalloc allocations, which zero-initialize memory
    const Expr *expr = Call.getOriginExpr();
    if (!expr)
      return;

    const CallExpr *CE = dyn_cast<CallExpr>(expr);
    if (!CE)
      return;

    const MemRegion *MR = getMemRegionFromExpr(CE, C);
    if (!MR)
      return;

    MR = MR->getBaseRegion();
    if (!MR)
      return;
    State = State->set<UninitMemoryMap>(MR, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  // Check for copy_to_user(user_dst, kernel_src, size)
  if (Callee->getName() == "copy_to_user") {
    SVal Arg1 = Call.getArgSVal(1);
    const MemRegion *MR = Arg1.getAsRegion();
    if (!MR)
      return;

    MR = MR->getBaseRegion();
    if (!MR)
      return;
    const bool *Uninit = State->get<UninitMemoryMap>(MR);
    if (Uninit && *Uninit) {
      reportInfoLeak(MR, C);
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const {

}

void SAGenTestChecker::reportInfoLeak(const MemRegion *MR, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential kernel information leak due to uninitialized kmalloc memory being copied to user space", N);
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects kernel information leaks by uninitialized kmalloc memory being copied to user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```



# Target Bug Pattern

## Bug Pattern

Unsynchronized cross-CPU access to a per-CPU counter: a per-CPU field is modified with plain read/modify/write (e.g., x += delta; x = 0) on one CPU while another CPU concurrently reads/clears the same field (via per_cpu_ptr(..., cpu)) without using READ_ONCE/WRITE_ONCE or other synchronization. This violates the “local-only” per-CPU assumption, causing data races and possible torn/lost updates.

# Target Patch

## Patch Description

memcg: fix data-race KCSAN bug in rstats

A data-race issue in memcg rstat occurs when two distinct code paths
access the same 4-byte region concurrently.  KCSAN detection triggers the
following BUG as a result.

	BUG: KCSAN: data-race in __count_memcg_events / mem_cgroup_css_rstat_flush

	write to 0xffffe8ffff98e300 of 4 bytes by task 5274 on cpu 17:
	mem_cgroup_css_rstat_flush (mm/memcontrol.c:5850)
	cgroup_rstat_flush_locked (kernel/cgroup/rstat.c:243 (discriminator 7))
	cgroup_rstat_flush (./include/linux/spinlock.h:401 kernel/cgroup/rstat.c:278)
	mem_cgroup_flush_stats.part.0 (mm/memcontrol.c:767)
	memory_numa_stat_show (mm/memcontrol.c:6911)
<snip>

	read to 0xffffe8ffff98e300 of 4 bytes by task 410848 on cpu 27:
	__count_memcg_events (mm/memcontrol.c:725 mm/memcontrol.c:962)
	count_memcg_event_mm.part.0 (./include/linux/memcontrol.h:1097 ./include/linux/memcontrol.h:1120)
	handle_mm_fault (mm/memory.c:5483 mm/memory.c:5622)
<snip>

	value changed: 0x00000029 -> 0x00000000

The race occurs because two code paths access the same "stats_updates"
location.  Although "stats_updates" is a per-CPU variable, it is remotely
accessed by another CPU at
cgroup_rstat_flush_locked()->mem_cgroup_css_rstat_flush(), leading to the
data race mentioned.

Considering that memcg_rstat_updated() is in the hot code path, adding a
lock to protect it may not be desirable, especially since this variable
pertains solely to statistics.

Therefore, annotating accesses to stats_updates with READ/WRITE_ONCE() can
prevent KCSAN splats and potential partial reads/writes.

Link: https://lkml.kernel.org/r/20240424125940.2410718-1-leitao@debian.org
Fixes: 9cee7e8ef3e3 ("mm: memcg: optimize parent iteration in memcg_rstat_updated()")
Signed-off-by: Breno Leitao <leitao@debian.org>
Suggested-by: Shakeel Butt <shakeel.butt@linux.dev>
Acked-by: Johannes Weiner <hannes@cmpxchg.org>
Acked-by: Shakeel Butt <shakeel.butt@linux.dev>
Reviewed-by: Yosry Ahmed <yosryahmed@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Muchun Song <songmuchun@bytedance.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>

## Buggy Code

```c
// Function: memcg_rstat_updated in mm/memcontrol.c
static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
{
	struct memcg_vmstats_percpu *statc;
	int cpu = smp_processor_id();

	if (!val)
		return;

	cgroup_rstat_updated(memcg->css.cgroup, cpu);
	statc = this_cpu_ptr(memcg->vmstats_percpu);
	for (; statc; statc = statc->parent) {
		statc->stats_updates += abs(val);
		if (statc->stats_updates < MEMCG_CHARGE_BATCH)
			continue;

		/*
		 * If @memcg is already flush-able, increasing stats_updates is
		 * redundant. Avoid the overhead of the atomic update.
		 */
		if (!memcg_vmstats_needs_flush(statc->vmstats))
			atomic64_add(statc->stats_updates,
				     &statc->vmstats->stats_updates);
		statc->stats_updates = 0;
	}
}
```

```c
// Function: mem_cgroup_css_rstat_flush in mm/memcontrol.c
static void mem_cgroup_css_rstat_flush(struct cgroup_subsys_state *css, int cpu)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	struct mem_cgroup *parent = parent_mem_cgroup(memcg);
	struct memcg_vmstats_percpu *statc;
	long delta, delta_cpu, v;
	int i, nid;

	statc = per_cpu_ptr(memcg->vmstats_percpu, cpu);

	for (i = 0; i < MEMCG_NR_STAT; i++) {
		/*
		 * Collect the aggregated propagation counts of groups
		 * below us. We're in a per-cpu loop here and this is
		 * a global counter, so the first cycle will get them.
		 */
		delta = memcg->vmstats->state_pending[i];
		if (delta)
			memcg->vmstats->state_pending[i] = 0;

		/* Add CPU changes on this level since the last flush */
		delta_cpu = 0;
		v = READ_ONCE(statc->state[i]);
		if (v != statc->state_prev[i]) {
			delta_cpu = v - statc->state_prev[i];
			delta += delta_cpu;
			statc->state_prev[i] = v;
		}

		/* Aggregate counts on this level and propagate upwards */
		if (delta_cpu)
			memcg->vmstats->state_local[i] += delta_cpu;

		if (delta) {
			memcg->vmstats->state[i] += delta;
			if (parent)
				parent->vmstats->state_pending[i] += delta;
		}
	}

	for (i = 0; i < NR_MEMCG_EVENTS; i++) {
		delta = memcg->vmstats->events_pending[i];
		if (delta)
			memcg->vmstats->events_pending[i] = 0;

		delta_cpu = 0;
		v = READ_ONCE(statc->events[i]);
		if (v != statc->events_prev[i]) {
			delta_cpu = v - statc->events_prev[i];
			delta += delta_cpu;
			statc->events_prev[i] = v;
		}

		if (delta_cpu)
			memcg->vmstats->events_local[i] += delta_cpu;

		if (delta) {
			memcg->vmstats->events[i] += delta;
			if (parent)
				parent->vmstats->events_pending[i] += delta;
		}
	}

	for_each_node_state(nid, N_MEMORY) {
		struct mem_cgroup_per_node *pn = memcg->nodeinfo[nid];
		struct mem_cgroup_per_node *ppn = NULL;
		struct lruvec_stats_percpu *lstatc;

		if (parent)
			ppn = parent->nodeinfo[nid];

		lstatc = per_cpu_ptr(pn->lruvec_stats_percpu, cpu);

		for (i = 0; i < NR_VM_NODE_STAT_ITEMS; i++) {
			delta = pn->lruvec_stats.state_pending[i];
			if (delta)
				pn->lruvec_stats.state_pending[i] = 0;

			delta_cpu = 0;
			v = READ_ONCE(lstatc->state[i]);
			if (v != lstatc->state_prev[i]) {
				delta_cpu = v - lstatc->state_prev[i];
				delta += delta_cpu;
				lstatc->state_prev[i] = v;
			}

			if (delta_cpu)
				pn->lruvec_stats.state_local[i] += delta_cpu;

			if (delta) {
				pn->lruvec_stats.state[i] += delta;
				if (ppn)
					ppn->lruvec_stats.state_pending[i] += delta;
			}
		}
	}
	statc->stats_updates = 0;
	/* We are in a per-cpu loop here, only do the atomic write once */
	if (atomic64_read(&memcg->vmstats->stats_updates))
		atomic64_set(&memcg->vmstats->stats_updates, 0);
}
```

## Bug Fix Patch

```diff
diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 9095ab05d47a..a111e0d981ba 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -715,6 +715,7 @@ static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
 {
 	struct memcg_vmstats_percpu *statc;
 	int cpu = smp_processor_id();
+	unsigned int stats_updates;

 	if (!val)
 		return;
@@ -722,8 +723,9 @@ static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
 	cgroup_rstat_updated(memcg->css.cgroup, cpu);
 	statc = this_cpu_ptr(memcg->vmstats_percpu);
 	for (; statc; statc = statc->parent) {
-		statc->stats_updates += abs(val);
-		if (statc->stats_updates < MEMCG_CHARGE_BATCH)
+		stats_updates = READ_ONCE(statc->stats_updates) + abs(val);
+		WRITE_ONCE(statc->stats_updates, stats_updates);
+		if (stats_updates < MEMCG_CHARGE_BATCH)
 			continue;

 		/*
@@ -731,9 +733,9 @@ static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
 		 * redundant. Avoid the overhead of the atomic update.
 		 */
 		if (!memcg_vmstats_needs_flush(statc->vmstats))
-			atomic64_add(statc->stats_updates,
+			atomic64_add(stats_updates,
 				     &statc->vmstats->stats_updates);
-		statc->stats_updates = 0;
+		WRITE_ONCE(statc->stats_updates, 0);
 	}
 }

@@ -5887,7 +5889,7 @@ static void mem_cgroup_css_rstat_flush(struct cgroup_subsys_state *css, int cpu)
 			}
 		}
 	}
-	statc->stats_updates = 0;
+	WRITE_ONCE(statc->stats_updates, 0);
 	/* We are in a per-cpu loop here, only do the atomic write once */
 	if (atomic64_read(&memcg->vmstats->stats_updates))
 		atomic64_set(&memcg->vmstats->stats_updates, 0);
```


# Target Plan

1) Program state customization

- REGISTER_MAP_WITH_PROGRAMSTATE(PerCpuPtrMap, const MemRegion*, unsigned)
  - Tracks pointer variables that point to per-CPU storage and how they were obtained.
  - Value is a bitmask:
    - bit 0 (1): isTracked (always set for entries)
    - bit 1 (2): isRemote (true if obtained via per_cpu_ptr(..., cpu) where cpu != smp_processor_id(); false if via this_cpu_ptr(...) or per_cpu_ptr(..., smp_processor_id()))
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple aliases between pointer variables so access classification can be propagated (p2 = p1).

Rationale:
- We only need to know whether a pointer variable is a per-CPU pointer and whether it represents a “remote” per-cpu access or a “local (this CPU)” per-cpu access. This is enough to detect missing READ_ONCE/WRITE_ONCE on remote access and RMW patterns on local access.


2) Callbacks and how to implement them

A. checkPostStmt(const DeclStmt *DS, CheckerContext &C) const
- Goal: Track initializations of pointer variables from per_cpu_ptr/this_cpu_ptr.
- Steps:
  - Iterate each VarDecl with an initializer in DS.
  - If the initializer is or contains a CallExpr:
    - Extract callee name string via getDirectCallee()->getNameAsString() (if available), otherwise use ExprHasName on the initializer expression with "per_cpu_ptr" or "this_cpu_ptr".
    - If it is per_cpu_ptr or this_cpu_ptr:
      - Determine “remote vs local”:
        - For this_cpu_ptr => local (isRemote = false).
        - For per_cpu_ptr(..., cpuExpr):
          - If cpuExpr contains "smp_processor_id" by ExprHasName(cpuExpr, "smp_processor_id"), mark local; else mark remote (isRemote = true).
      - Obtain the MemRegion of the declared variable using getMemRegionFromExpr on a DeclRefExpr to the VarDecl (you can get it by creating a DeclRefExpr from the VarDecl or, simpler, by using State->getLValue(VarDecl, LCtx).getAsRegion()).
      - Insert into PerCpuPtrMap: (VarRegion -> flags: isTracked | isRemote?2:0).
  - This step ensures we start tracking pointer variables bound to per-CPU storage and whether the access is “remote” or “local” by construction.

B. checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- Goal: Track assignments to pointer variables either from per_cpu_ptr/this_cpu_ptr or from another tracked pointer (alias propagation).
- Steps:
  - Identify LHS region: if Loc is a MemRegionVal for a pointer-typed Var/Field, get MemRegion* LHSReg.
  - If S is a BinaryOperator with isAssignmentOp():
    - Extract RHS expression R:
      - If R contains a CallExpr to per_cpu_ptr/this_cpu_ptr (use findSpecificTypeInChildren<CallExpr>(R) and name matching as in A):
        - Determine “remote vs local” same way as in A.
        - Map LHSReg -> flags in PerCpuPtrMap (overwrite previous).
      - Else if RHS is a pointer variable already in PerCpuPtrMap:
        - Use getMemRegionFromExpr on RHS to get RHSReg.
        - If RHSReg is in PerCpuPtrMap, copy flags from RHSReg to LHSReg and also set PtrAliasMap[LHSReg] = RHSReg.
      - Else:
        - If LHSReg was tracked and RHS is not per-cpu/alias, you may remove LHSReg from PerCpuPtrMap (optional hygiene). Not strictly required for this checker to work.

C. checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const
- Goal: Detect read-modify-write on per-CPU fields without READ_ONCE/WRITE_ONCE.
- Steps:
  - Let LHS = CAO->getLHS()->IgnoreParenImpCasts().
  - If LHS is (or contains) a MemberExpr (e.g., statc->field or statc->arr[i]):
    - Extract the base expression B = MemberExpr->getBase()->IgnoreParenImpCasts().
    - If B is a DeclRefExpr to a pointer variable:
      - Get its MemRegion via getMemRegionFromExpr(B, C).
      - If in PerCpuPtrMap as isTracked:
        - If it is a per-CPU pointer (local or remote — for remote we’ll also catch in checkLocation), warn specifically for RMW on per-CPU field:
          - Message: "Per-CPU field updated with compound assignment without READ_ONCE/WRITE_ONCE."
        - Rationale: Kernel fix replaced x += delta with explicit READ_ONCE/WRITE_ONCE sequence; compound ops are inherently RMW and should be avoided here.

D. checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const
- Goal: Detect ++/-- on per-CPU fields without READ_ONCE/WRITE_ONCE.
- Steps:
  - If UO is increment/decrement and its subexpr is a MemberExpr on a tracked per-CPU pointer (as identified in C), report:
    - "Per-CPU field increment/decrement without READ_ONCE/WRITE_ONCE."

E. checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const
- Goal: Enforce READ_ONCE on remote reads and WRITE_ONCE on remote writes; also catch simple writes on per-CPU fields missing WRITE_ONCE.
- Steps:
  - If S is not an Expr, return.
  - Using findSpecificTypeInChildren<MemberExpr>(cast<Expr>(S)):
    - If found, extract MemberExpr (ME).
    - Obtain the base expression B = ME->getBase()->IgnoreParenImpCasts().
    - If B is a DeclRefExpr to a pointer variable:
      - Get MemRegion BReg via getMemRegionFromExpr(B, C).
      - If BReg is tracked in PerCpuPtrMap:
        - Determine whether this is a remote pointer (isRemote flag).
        - Check macro wrapping:
          - Use ExprHasName(cast<Expr>(S), "READ_ONCE") for reads and ExprHasName(cast<Expr>(S), "WRITE_ONCE") for writes. Additionally, check parents for fallback: climb via findSpecificTypeInParents<Expr>(S, C) if needed and apply ExprHasName to the nearest parent Expression (best-effort).
        - If IsLoad and isRemote and not wrapped by READ_ONCE, report:
          - "Remote per-CPU read without READ_ONCE."
        - If !IsLoad (store) and isRemote and not wrapped by WRITE_ONCE, report:
          - "Remote per-CPU write without WRITE_ONCE."
        - Optional conservative rule (helps catch the 'x = 0' local clear in hot path):
          - If !IsLoad and not wrapped by WRITE_ONCE (regardless of isRemote), report:
            - "Per-CPU field write without WRITE_ONCE; may race with cross-CPU access."
          - This is a heuristic to surface risky plain writes to per-CPU counters. If you want to be stricter, only enable this when isRemote == true.

F. checkBind (alias propagation)
- Already specified in B. Also, when p2 = p1 and p1 is in PtrAliasMap, transitively map to the ultimate source so that future lookups for p2 resolve to the same flags.
- If a tracked pointer is assigned NULL or some non-percpu expression, optionally remove from PerCpuPtrMap.

G. Reporting
- On each violation above, create a non-fatal error node and emit a short bug report:
  - Use std::make_unique<PathSensitiveBugReport>.
  - Example messages:
    - "Remote per-CPU read without READ_ONCE."
    - "Remote per-CPU write without WRITE_ONCE."
    - "Per-CPU field updated with compound assignment without READ_ONCE/WRITE_ONCE."
    - "Per-CPU field increment/decrement without READ_ONCE/WRITE_ONCE."
    - "Per-CPU field write without WRITE_ONCE; may race with cross-CPU access."

3) Helper details and heuristics

- Identifying per_cpu_ptr/this_cpu_ptr:
  - Prefer matching via callee identifier name when CallExpr->getDirectCallee() exists.
  - Otherwise, rely on ExprHasName(InitOrRHSExpr, "per_cpu_ptr") or ExprHasName(..., "this_cpu_ptr").
- Determining "remote":
  - For per_cpu_ptr(base, cpuExpr): examine cpuExpr via ExprHasName(cpuExpr, "smp_processor_id"). If it contains "smp_processor_id", classify as local; otherwise remote.
  - For this_cpu_ptr(...): classify as local.
- Finding MemberExpr inside S in checkLocation:
  - Use findSpecificTypeInChildren<MemberExpr>(cast<Expr>(S)) to get the member access causing the load/store. This works for both direct field and array element cases (e.g., statc->arr[i]).
- Macro checks:
  - Using ExprHasName on the source of the expression S to detect "READ_ONCE" or "WRITE_ONCE". This is robust for Linux macro usage and avoids needing to inspect volatile qualifiers in the AST.
- Aliases:
  - For p2 = p1 where both are pointers, if p1 is tracked, map p2 with same flags. Maintain PtrAliasMap to chain aliases. On lookup, resolve transitively to the ultimate source if needed (best-effort).

4) Minimal set of callbacks to implement

- checkPostStmt(const DeclStmt *DS, CheckerContext &C) const
- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
- checkPreStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const
- checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const
- checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const

This set keeps the checker simple and focused:
- Build a map of per-CPU pointers and whether they imply remote access.
- Flag unsafe remote reads/writes not wrapped with READ_ONCE/WRITE_ONCE.
- Flag RMW patterns on per-CPU fields lacking READ_ONCE/WRITE_ONCE.
- Optionally flag plain writes to per-CPU fields not using WRITE_ONCE.

# Checker Template

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
{{Add your includes here}}

using namespace clang;
using namespace ento;
using namespace taint;

{{Customize program states}} // If necessary

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<{{Callback Functions}}> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "{{Bug Group}}", "{{Bug Type}}")) {}

      {{Declaration of Callback Functions}}

   private:

      {{Declaration of Self-Defined Functions}}
};

{{Your Functions: functions should be complete and runable}}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "{{Checker descriptions to be filled}}",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```


# Formatting

Please show me the completed checker.

Your response should be like:

```cpp
{{checker code here}}
```
