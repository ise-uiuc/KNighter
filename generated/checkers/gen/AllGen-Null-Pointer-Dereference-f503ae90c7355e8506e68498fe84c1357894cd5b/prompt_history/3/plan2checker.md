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

Dereferencing a capability pointer returned by a getter that may return NULL without first validating it. Specifically, using fields of the pointer (e.g., vc->he_cap_elem / ve->phy_cap_info[…]) before checking that vc is non-NULL:
- vc = mt76_connac_get_he_phy_cap(...)
- ve = &vc->he_cap_elem;   // computed before validation
- ... use ve->...          // dereference causes NULL pointer deref if vc is NULL

Root cause: missing NULL check on the result of a capability retrieval helper before accessing its members.

# Target Patch

## Patch Description

wifi: mt76: mt7996: fix NULL pointer dereference in mt7996_mcu_sta_bfer_he

Fix the NULL pointer dereference in mt7996_mcu_sta_bfer_he
routine adding an sta interface to the mt7996 driver.

Found by code review.

Cc: stable@vger.kernel.org
Fixes: 98686cd21624 ("wifi: mt76: mt7996: add driver for MediaTek Wi-Fi 7 (802.11be) devices")
Signed-off-by: Ma Ke <make24@iscas.ac.cn>
Link: https://patch.msgid.link/20240813081242.3991814-1-make24@iscas.ac.cn
Signed-off-by: Felix Fietkau <nbd@nbd.name>

## Buggy Code

```c
// Function: mt7996_mcu_sta_bfer_he in drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
static void
mt7996_mcu_sta_bfer_he(struct ieee80211_sta *sta, struct ieee80211_vif *vif,
		       struct mt7996_phy *phy, struct sta_rec_bf *bf)
{
	struct ieee80211_sta_he_cap *pc = &sta->deflink.he_cap;
	struct ieee80211_he_cap_elem *pe = &pc->he_cap_elem;
	const struct ieee80211_sta_he_cap *vc =
		mt76_connac_get_he_phy_cap(phy->mt76, vif);
	const struct ieee80211_he_cap_elem *ve = &vc->he_cap_elem;
	u16 mcs_map = le16_to_cpu(pc->he_mcs_nss_supp.rx_mcs_80);
	u8 nss_mcs = mt7996_mcu_get_sta_nss(mcs_map);
	u8 snd_dim, sts;

	bf->tx_mode = MT_PHY_TYPE_HE_SU;

	mt7996_mcu_sta_sounding_rate(bf);

	bf->trigger_su = HE_PHY(CAP6_TRIG_SU_BEAMFORMING_FB,
				pe->phy_cap_info[6]);
	bf->trigger_mu = HE_PHY(CAP6_TRIG_MU_BEAMFORMING_PARTIAL_BW_FB,
				pe->phy_cap_info[6]);
	snd_dim = HE_PHY(CAP5_BEAMFORMEE_NUM_SND_DIM_UNDER_80MHZ_MASK,
			 ve->phy_cap_info[5]);
	sts = HE_PHY(CAP4_BEAMFORMEE_MAX_STS_UNDER_80MHZ_MASK,
		     pe->phy_cap_info[4]);
	bf->nrow = min_t(u8, snd_dim, sts);
	bf->ncol = min_t(u8, nss_mcs, bf->nrow);
	bf->ibf_ncol = bf->ncol;

	if (sta->deflink.bandwidth != IEEE80211_STA_RX_BW_160)
		return;

	/* go over for 160MHz and 80p80 */
	if (pe->phy_cap_info[0] &
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G) {
		mcs_map = le16_to_cpu(pc->he_mcs_nss_supp.rx_mcs_160);
		nss_mcs = mt7996_mcu_get_sta_nss(mcs_map);

		bf->ncol_gt_bw80 = nss_mcs;
	}

	if (pe->phy_cap_info[0] &
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G) {
		mcs_map = le16_to_cpu(pc->he_mcs_nss_supp.rx_mcs_80p80);
		nss_mcs = mt7996_mcu_get_sta_nss(mcs_map);

		if (bf->ncol_gt_bw80)
			bf->ncol_gt_bw80 = min_t(u8, bf->ncol_gt_bw80, nss_mcs);
		else
			bf->ncol_gt_bw80 = nss_mcs;
	}

	snd_dim = HE_PHY(CAP5_BEAMFORMEE_NUM_SND_DIM_ABOVE_80MHZ_MASK,
			 ve->phy_cap_info[5]);
	sts = HE_PHY(CAP4_BEAMFORMEE_MAX_STS_ABOVE_80MHZ_MASK,
		     pe->phy_cap_info[4]);

	bf->nrow_gt_bw80 = min_t(int, snd_dim, sts);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
index e8d34bfbb41a..8855095fef10 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
@@ -1544,6 +1544,9 @@ mt7996_mcu_sta_bfer_he(struct ieee80211_sta *sta, struct ieee80211_vif *vif,
 	u8 nss_mcs = mt7996_mcu_get_sta_nss(mcs_map);
 	u8 snd_dim, sts;

+	if (!vc)
+		return;
+
 	bf->tx_mode = MT_PHY_TYPE_HE_SU;

 	mt7996_mcu_sta_sounding_rate(bf);
```


# Target Plan

Plan: Detect dereferencing a capability pointer returned by a getter that may be NULL (e.g., mt76_connac_get_he_phy_cap) before validating it

1. Program state
- Use a simple state map to track pointers that originate from possibly-NULL getters and whether they have been checked:
  - REGISTER_MAP_WITH_PROGRAMSTATE(NullCkMap, const MemRegion*, bool)
    - Value false: result originates from a possibly-NULL getter and has not been checked.
    - Value true: the pointer (or an alias) has been checked in some condition.
- Track basic aliasing so that checks or uses propagate:
  - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
    - Maps a pointer region to its “root/source” region (the original getter result). If a pointer is assigned from another pointer, link the destination to the source so their “checked” state is shared.
- Helper: findRootAlias(State, R)
  - Follow PtrAliasMap links until no mapping exists; return the canonical root region to be used for lookups/updates in NullCkMap.

2. Callbacks and logic

A. checkPostCall (mark possibly-NULL getter results)
- Goal: When a known getter that can return NULL is called, mark its return as unchecked.
- Implementation:
  - Implement isKnownPossiblyNullGetter(const CallEvent &Call):
    - Return true if callee name equals "mt76_connac_get_he_phy_cap".
    - Keep it simple and exact to avoid false positives.
  - If true:
    - Obtain the return expression (Call.getOriginExpr()) and get its MemRegion using getMemRegionFromExpr.
    - If region exists, insert into NullCkMap with value false (unchecked).
    - Clear any PtrAliasMap mapping for this region (make it its own root).

B. checkBind (propagate aliases; detect “&ptr->field” deref)
- Goal 1: Track pointer aliasing p2 = p1.
  - If Loc is a region for a pointer-typed variable and Val is a region (another pointer):
    - Let Rdst be destination region (from Loc) and Rsrc be source region (from Val).
    - Compute SrcRoot = findRootAlias(State, Rsrc).
    - If SrcRoot is in NullCkMap:
      - Set PtrAliasMap[Rdst] = SrcRoot (link destination to source root).
      - If NullCkMap contains Rdst with a different root, overwrite that with SrcRoot.
      - Do not mark as checked here; just propagate the unchecked/checked status from SrcRoot when needed by always querying Root.
- Goal 2: Catch deref via address-of member expression, e.g., ve = &vc->he_cap_elem;
  - The expression does dereference the pointer even if using &.
  - In checkBind, inspect S (the assignment/initialization stmt):
    - Find a UnaryOperator child that is address-of (&).
    - Inside it, find a MemberExpr child with isArrow() true (->).
    - Get the base expression of that MemberExpr and its MemRegion via getMemRegionFromExpr.
    - Resolve Root = findRootAlias(State, BaseRegion).
    - If Root is in NullCkMap with value false (unchecked), report a bug (see Reporting).
  - This complements checkLocation for the case where taking & of a member may not trigger a load.

C. checkLocation (detect deref uses such as p->f, *p, p[i])
- Goal: When a load/store implicitly dereferences a pointer that is known unchecked from a possibly-NULL getter, emit a warning.
- Implementation:
  - Given Loc and S:
    - Try to identify base pointer expressions for common deref patterns in S:
      - MemberExpr with isArrow() true: base expression is the pointer being dereferenced.
      - UnaryOperator with opcode UO_Deref (*p): the subexpr is the pointer.
      - ArraySubscriptExpr p[i]: the base is the pointer.
    - Use findSpecificTypeInChildren<MemberExpr/UnaryOperator/ArraySubscriptExpr>(S) to detect these, preferring MemberExpr(->) if present.
    - Extract the base expression, get its MemRegion via getMemRegionFromExpr.
    - Resolve Root = findRootAlias(State, BaseRegion).
    - If Root exists in NullCkMap with value false (unchecked), emit a report.
  - Optional conservative filter: If there is no tracked region, do nothing; if it’s tracked and checked, do nothing.

D. checkBranchCondition (mark pointers as checked when referenced in a condition)
- Goal: If the code references a tracked pointer in a condition (if (vc), if (vc != NULL), if (!vc), etc.), mark it as checked to reduce false positives afterward.
- Implementation:
  - Given Condition:
    - Find any DeclRefExpr child; get its MemRegion via getMemRegionFromExpr.
    - For each such region:
      - Resolve Root = findRootAlias(State, Region).
      - If Root is in NullCkMap with value false, update that entry to true (checked).
  - Note: This is a conservative heuristic. We don’t attempt to track branch direction; we just mark as checked once a condition references the pointer, which is adequate for catching the immediate “dereference before check” pattern and reducing later false positives.

3. Reporting
- Create a BugType once (e.g., "Possible NULL dereference of capability pointer").
- On detection in checkLocation/checkBind:
  - Generate a non-fatal error node.
  - Emit a PathSensitiveBugReport with a short message:
    - "Dereference of possibly NULL capability pointer returned by mt76_connac_get_he_phy_cap"
  - Optionally, add a note range to the dereferencing expression (MemberExpr/UnaryOperator/ArraySubscriptExpr) to highlight the exact use site.

4. Notes on utilities usage
- Use getMemRegionFromExpr to convert base expressions and call expressions into MemRegion keys for the maps.
- Use findSpecificTypeInChildren to locate MemberExpr/UnaryOperator/ArraySubscriptExpr within S for deref detection.
- For branch condition handling, DeclRefExpr is sufficient; we do not need to resolve NULL constants explicitly.
- No need to customize evalAssume or constraints; keep the checker simple and focused on the immediate pattern.

5. Summary of minimal steps
- Track results of mt76_connac_get_he_phy_cap as unchecked (checkPostCall).
- Propagate pointer aliasing on assignments (checkBind).
- Detect dereferences via:
  - checkLocation for p->f, *p, p[i].
  - checkBind for &p->f.
- Mark pointers as checked when they appear in a branch condition (checkBranchCondition).
- Report when an unchecked pointer is dereferenced.

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
