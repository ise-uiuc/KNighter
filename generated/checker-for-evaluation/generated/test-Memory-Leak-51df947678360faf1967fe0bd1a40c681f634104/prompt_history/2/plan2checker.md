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

## Example 2
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

## Example 3
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



# Target Bug Pattern

## Bug Pattern

The bug pattern is a missing cleanup in an error handling path where allocated memory is not freed. In this case, if rvu_rep_devlink_port_register() fails, the code does not free the netdev allocated via alloc_etherdev(), resulting in a memory leak. The root cause is the omission of the free_netdev() call on the erroneous iteration, which leaves the allocated memory unfreed and can accumulate over repeated failures.

# Target Patch

## Patch Description

octeontx2-pf: fix netdev memory leak in rvu_rep_create()

When rvu_rep_devlink_port_register() fails, free_netdev(ndev) for this
incomplete iteration before going to "exit:" label.

Fixes: 9ed0343f561e ("octeontx2-pf: Add devlink port support")
Reviewed-by: Przemek Kitszel <przemyslaw.kitszel@intel.com>
Signed-off-by: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>
Link: https://patch.msgid.link/20241217052326.1086191-1-harshit.m.mogalapalli@oracle.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>

## Buggy Code

```c
// drivers/net/ethernet/marvell/octeontx2/nic/rep.c
int rvu_rep_create(struct otx2_nic *priv, struct netlink_ext_ack *extack)
{
	int rep_cnt = priv->rep_cnt;
	struct net_device *ndev;
	struct rep_dev *rep;
	int rep_id, err;
	u16 pcifunc;

	err = rvu_rep_rsrc_init(priv);
	if (err)
		return -ENOMEM;

	priv->reps = kcalloc(rep_cnt, sizeof(struct rep_dev *), GFP_KERNEL);
	if (!priv->reps)
		return -ENOMEM;

	for (rep_id = 0; rep_id < rep_cnt; rep_id++) {
		ndev = alloc_etherdev(sizeof(*rep));
		if (!ndev) {
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "PFVF representor:%d creation failed",
					       rep_id);
			err = -ENOMEM;
			goto exit;
		}

		rep = netdev_priv(ndev);
		priv->reps[rep_id] = rep;
		rep->mdev = priv;
		rep->netdev = ndev;
		rep->rep_id = rep_id;

		ndev->min_mtu = OTX2_MIN_MTU;
		ndev->max_mtu = priv->hw.max_mtu;
		ndev->netdev_ops = &rvu_rep_netdev_ops;
		pcifunc = priv->rep_pf_map[rep_id];
		rep->pcifunc = pcifunc;

		snprintf(ndev->name, sizeof(ndev->name), "Rpf%dvf%d",
			 rvu_get_pf(pcifunc), (pcifunc & RVU_PFVF_FUNC_MASK));

		ndev->hw_features = (NETIF_F_RXCSUM | NETIF_F_IP_CSUM |
			       NETIF_F_IPV6_CSUM | NETIF_F_RXHASH |
			       NETIF_F_SG | NETIF_F_TSO | NETIF_F_TSO6);

		ndev->hw_features |= NETIF_F_HW_TC;
		ndev->features |= ndev->hw_features;
		eth_hw_addr_random(ndev);
		err = rvu_rep_devlink_port_register(rep);
		if (err)
			goto exit;

		SET_NETDEV_DEVLINK_PORT(ndev, &rep->dl_port);
		err = register_netdev(ndev);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack,
					   "PFVF representor registration failed");
			free_netdev(ndev);
			goto exit;
		}

		INIT_DELAYED_WORK(&rep->stats_wrk, rvu_rep_get_stats);
	}
	err = rvu_rep_napi_init(priv, extack);
	if (err)
		goto exit;

	rvu_eswitch_config(priv, true);
	return 0;
exit:
	while (--rep_id >= 0) {
		rep = priv->reps[rep_id];
		unregister_netdev(rep->netdev);
		rvu_rep_devlink_port_unregister(rep);
		free_netdev(rep->netdev);
	}
	kfree(priv->reps);
	rvu_rep_rsrc_free(priv);
	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/marvell/octeontx2/nic/rep.c b/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
index 232b10740c13..9e3fcbae5dee 100644
--- a/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
+++ b/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
@@ -680,8 +680,10 @@ int rvu_rep_create(struct otx2_nic *priv, struct netlink_ext_ack *extack)
 		ndev->features |= ndev->hw_features;
 		eth_hw_addr_random(ndev);
 		err = rvu_rep_devlink_port_register(rep);
-		if (err)
+		if (err) {
+			free_netdev(ndev);
 			goto exit;
+		}
 
 		SET_NETDEV_DEVLINK_PORT(ndev, &rep->dl_port);
 		err = register_netdev(ndev);
```



# Target Plan

Your plan is as follows:

------------------------------------------------------------
1. Decide on customizing program states:
   • REGISTER a map (e.g. NetdevStateMap) with program state to track netdev allocations:  
     REGISTER_MAP_WITH_PROGRAMSTATE(NetdevStateMap, const MemRegion*, bool)
   • The map will record every allocation from alloc_etherdev() by mapping its returned memory region (or alias) to a boolean flag indicating whether free_netdev() has been called (true means freed; false means still allocated).

2. Choose callback functions:
   A. In checkPostCall callback for function calls:
      1. For alloc_etherdev():
         • Recognize when a call is made to alloc_etherdev().
         • Extract the returned netdev pointer (obtain its MemRegion) and record it in the NetdevStateMap with a 'false' (not freed) flag.
      2. For free_netdev():
         • When a call to free_netdev() is encountered, extract the netdev pointer from the argument.
         • In the program state, mark that pointer’s entry as true (meaning the netdev has been freed).
      3. For rvu_rep_devlink_port_register():
         • After the call to rvu_rep_devlink_port_register(), use EvaluateExprToInt (or equivalent) to check whether the returned error code is nonzero.
         • If the error code is nonzero, it means the branch is error handling.
         • Retrieve (via parent/child lookups or via a stored alias from checkBind) the netdev pointer corresponding to the current iteration.
         • Query the NetdevStateMap – if the pointer is still flagged false (i.e. free_netdev has not been called), generate a bug report.

   B. In checkBind callback:
      • When the result of alloc_etherdev() is assigned to the local variable (for example, “ndev”), record the aliasing relationship.
      • This tracking will help to connect the allocated memory region with later calls to free_netdev() even if the pointer is propagated between variables.

3. Detailed implementation steps in the callbacks:
   • In checkPostCall for alloc_etherdev():
     – Identify that the call is to alloc_etherdev() by matching the callee name.
     – Get the returned SVal and convert that to a MemRegion.
     – Update the program state NetdevStateMap with {netdev region: false}.
   • In checkPostCall for free_netdev():
     – Check that the call is indeed to free_netdev() using the callee name.
     – Extract the pointer argument, get its MemRegion.
     – Update NetdevStateMap by marking the corresponding region as true.
   • In checkPostCall for rvu_rep_devlink_port_register():
     – Identify the call by matching its name.
     – Evaluate the returned integer error code. If it is nonzero:
         ▪ Use findSpecificTypeInParents or the alias information from checkBind to locate the associated netdev pointer allocated earlier.
         ▪ Lookup the netdev pointer in NetdevStateMap. If its flag remains false (meaning free_netdev() was not called in this error path), then prepare and emit a bug report with a concise message such as "Missing free_netdev in error handling".
   • In checkBind:
     – When a netdev pointer from alloc_etherdev() is bound to a variable (e.g. “ndev”), record the aliasing relation.
     – Later updates in free_netdev/rvu_rep_devlink_port_register will use this alias map to correctly identify the netdev region.

4. Bug Reporting:
   • Use a short and clear message.
   • Create a bug report (using std::make_unique<PathSensitiveBugReport> or BasicBugReport) when the error branch (after rvu_rep_devlink_port_register fails) is detected without a corresponding free_netdev call for the netdev pointer.
   
------------------------------------------------------------
This plan uses very few steps by leveraging two key callbacks (checkPostCall and checkBind) and a single customized program state map to track allocated memory. It ensures that when the error path is taken (i.e. rvu_rep_devlink_port_register returns an error), the checker verifies the proper cleanup of the allocated netdev.

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
/*The checker callbacks are to be decided.*/
class SAGenTestChecker : public Checker<{{Callback Functions}}> { 
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "{{Bug type description}}")) {}

      {{Declaration of Callback Functions}}

   private:

      {{Declaration of Sefl-defined Functions}}
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