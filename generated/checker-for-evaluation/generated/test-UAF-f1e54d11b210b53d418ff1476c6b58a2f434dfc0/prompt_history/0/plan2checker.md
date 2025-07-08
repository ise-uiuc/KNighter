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

Directly freeing a shared metadata object using metadata_dst_free() without proper reference counting can result in a premature free. This causes a use‐after‐free bug when the metadata object is still referenced by other parts of the code (such as offloading packets). The correct approach is to use a release function (dst_release()) that decrements the object's reference count, ensuring the object isn’t freed while still in use.

# Target Patch

## Patch Description

macsec: Fix use-after-free while sending the offloading packet

KASAN reports the following UAF. The metadata_dst, which is used to
store the SCI value for macsec offload, is already freed by
metadata_dst_free() in macsec_free_netdev(), while driver still use it
for sending the packet.

To fix this issue, dst_release() is used instead to release
metadata_dst. So it is not freed instantly in macsec_free_netdev() if
still referenced by skb.

 BUG: KASAN: slab-use-after-free in mlx5e_xmit+0x1e8f/0x4190 [mlx5_core]
 Read of size 2 at addr ffff88813e42e038 by task kworker/7:2/714
 [...]
 Workqueue: mld mld_ifc_work
 Call Trace:
  <TASK>
  dump_stack_lvl+0x51/0x60
  print_report+0xc1/0x600
  kasan_report+0xab/0xe0
  mlx5e_xmit+0x1e8f/0x4190 [mlx5_core]
  dev_hard_start_xmit+0x120/0x530
  sch_direct_xmit+0x149/0x11e0
  __qdisc_run+0x3ad/0x1730
  __dev_queue_xmit+0x1196/0x2ed0
  vlan_dev_hard_start_xmit+0x32e/0x510 [8021q]
  dev_hard_start_xmit+0x120/0x530
  __dev_queue_xmit+0x14a7/0x2ed0
  macsec_start_xmit+0x13e9/0x2340
  dev_hard_start_xmit+0x120/0x530
  __dev_queue_xmit+0x14a7/0x2ed0
  ip6_finish_output2+0x923/0x1a70
  ip6_finish_output+0x2d7/0x970
  ip6_output+0x1ce/0x3a0
  NF_HOOK.constprop.0+0x15f/0x190
  mld_sendpack+0x59a/0xbd0
  mld_ifc_work+0x48a/0xa80
  process_one_work+0x5aa/0xe50
  worker_thread+0x79c/0x1290
  kthread+0x28f/0x350
  ret_from_fork+0x2d/0x70
  ret_from_fork_asm+0x11/0x20
  </TASK>

 Allocated by task 3922:
  kasan_save_stack+0x20/0x40
  kasan_save_track+0x10/0x30
  __kasan_kmalloc+0x77/0x90
  __kmalloc_noprof+0x188/0x400
  metadata_dst_alloc+0x1f/0x4e0
  macsec_newlink+0x914/0x1410
  __rtnl_newlink+0xe08/0x15b0
  rtnl_newlink+0x5f/0x90
  rtnetlink_rcv_msg+0x667/0xa80
  netlink_rcv_skb+0x12c/0x360
  netlink_unicast+0x551/0x770
  netlink_sendmsg+0x72d/0xbd0
  __sock_sendmsg+0xc5/0x190
  ____sys_sendmsg+0x52e/0x6a0
  ___sys_sendmsg+0xeb/0x170
  __sys_sendmsg+0xb5/0x140
  do_syscall_64+0x4c/0x100
  entry_SYSCALL_64_after_hwframe+0x4b/0x53

 Freed by task 4011:
  kasan_save_stack+0x20/0x40
  kasan_save_track+0x10/0x30
  kasan_save_free_info+0x37/0x50
  poison_slab_object+0x10c/0x190
  __kasan_slab_free+0x11/0x30
  kfree+0xe0/0x290
  macsec_free_netdev+0x3f/0x140
  netdev_run_todo+0x450/0xc70
  rtnetlink_rcv_msg+0x66f/0xa80
  netlink_rcv_skb+0x12c/0x360
  netlink_unicast+0x551/0x770
  netlink_sendmsg+0x72d/0xbd0
  __sock_sendmsg+0xc5/0x190
  ____sys_sendmsg+0x52e/0x6a0
  ___sys_sendmsg+0xeb/0x170
  __sys_sendmsg+0xb5/0x140
  do_syscall_64+0x4c/0x100
  entry_SYSCALL_64_after_hwframe+0x4b/0x53

Fixes: 0a28bfd4971f ("net/macsec: Add MACsec skb_metadata_dst Tx Data path support")
Signed-off-by: Jianbo Liu <jianbol@nvidia.com>
Reviewed-by: Patrisious Haddad <phaddad@nvidia.com>
Reviewed-by: Chris Mi <cmi@nvidia.com>
Signed-off-by: Tariq Toukan <tariqt@nvidia.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Reviewed-by: Sabrina Dubroca <sd@queasysnail.net>
Link: https://patch.msgid.link/20241021100309.234125-1-tariqt@nvidia.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>

## Buggy Code

```c
// drivers/net/macsec.c
static int macsec_upd_rxsc(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **attrs = info->attrs;
	struct net_device *dev;
	struct macsec_secy *secy;
	struct macsec_rx_sc *rx_sc;
	struct nlattr *tb_rxsc[MACSEC_RXSC_ATTR_MAX + 1];
	unsigned int prev_n_rx_sc;
	bool was_active;
	int ret;

	if (!attrs[MACSEC_ATTR_IFINDEX])
		return -EINVAL;

	if (parse_rxsc_config(attrs, tb_rxsc))
		return -EINVAL;

	if (!validate_add_rxsc(tb_rxsc))
		return -EINVAL;

	rtnl_lock();
	rx_sc = get_rxsc_from_nl(genl_info_net(info), attrs, tb_rxsc, &dev, &secy);
	if (IS_ERR(rx_sc)) {
		rtnl_unlock();
		return PTR_ERR(rx_sc);
	}

	was_active = rx_sc->active;
	prev_n_rx_sc = secy->n_rx_sc;
	if (tb_rxsc[MACSEC_RXSC_ATTR_ACTIVE]) {
		bool new = !!nla_get_u8(tb_rxsc[MACSEC_RXSC_ATTR_ACTIVE]);

		if (rx_sc->active != new)
			secy->n_rx_sc += new ? 1 : -1;

		rx_sc->active = new;
	}

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(netdev_priv(dev))) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(netdev_priv(dev), &ctx);
		if (!ops) {
			ret = -EOPNOTSUPP;
			goto cleanup;
		}

		ctx.rx_sc = rx_sc;
		ctx.secy = secy;

		ret = macsec_offload(ops->mdo_upd_rxsc, &ctx);
		if (ret)
			goto cleanup;
	}

	rtnl_unlock();

	return 0;

cleanup:
	secy->n_rx_sc = prev_n_rx_sc;
	rx_sc->active = was_active;
	rtnl_unlock();
	return ret;
}

static bool macsec_is_configured(struct macsec_dev *macsec)
{
	struct macsec_secy *secy = &macsec->secy;
	struct macsec_tx_sc *tx_sc = &secy->tx_sc;
	int i;

	if (secy->rx_sc)
		return true;

	for (i = 0; i < MACSEC_NUM_AN; i++)
		if (tx_sc->sa[i])
			return true;

	return false;
}

static bool macsec_needs_tx_tag(struct macsec_dev *macsec,
				const struct macsec_ops *ops)
{
	return macsec->offload == MACSEC_OFFLOAD_PHY &&
		ops->mdo_insert_tx_tag;
}

static void macsec_set_head_tail_room(struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;
	int needed_headroom, needed_tailroom;
	const struct macsec_ops *ops;

	ops = macsec_get_ops(macsec, NULL);
	if (ops) {
		needed_headroom = ops->needed_headroom;
		needed_tailroom = ops->needed_tailroom;
	} else {
		needed_headroom = MACSEC_NEEDED_HEADROOM;
		needed_tailroom = MACSEC_NEEDED_TAILROOM;
	}

	dev->needed_headroom = real_dev->needed_headroom + needed_headroom;
	dev->needed_tailroom = real_dev->needed_tailroom + needed_tailroom;
}

static int macsec_update_offload(struct net_device *dev, enum macsec_offload offload)
{
	enum macsec_offload prev_offload;
	const struct macsec_ops *ops;
	struct macsec_context ctx;
	struct macsec_dev *macsec;
	int ret = 0;

	macsec = macsec_priv(dev);

	/* Check if the offloading mode is supported by the underlying layers */
	if (offload != MACSEC_OFFLOAD_OFF &&
	    !macsec_check_offload(offload, macsec))
		return -EOPNOTSUPP;

	/* Check if the net device is busy. */
	if (netif_running(dev))
		return -EBUSY;

	/* Check if the device already has rules configured: we do not support
	 * rules migration.
	 */
	if (macsec_is_configured(macsec))
		return -EBUSY;

	prev_offload = macsec->offload;

	ops = __macsec_get_ops(offload == MACSEC_OFFLOAD_OFF ? prev_offload : offload,
			       macsec, &ctx);
	if (!ops)
		return -EOPNOTSUPP;

	macsec->offload = offload;

	ctx.secy = &macsec->secy;
	ret = offload == MACSEC_OFFLOAD_OFF ? macsec_offload(ops->mdo_del_secy, &ctx)
					    : macsec_offload(ops->mdo_add_secy, &ctx);
	if (ret) {
		macsec->offload = prev_offload;
		return ret;
	}

	macsec_set_head_tail_room(dev);
	macsec->insert_tx_tag = macsec_needs_tx_tag(macsec, ops);

	return ret;
}

static int macsec_upd_offload(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *tb_offload[MACSEC_OFFLOAD_ATTR_MAX + 1];
	struct nlattr **attrs = info->attrs;
	enum macsec_offload offload;
	struct macsec_dev *macsec;
	struct net_device *dev;
	int ret = 0;

	if (!attrs[MACSEC_ATTR_IFINDEX])
		return -EINVAL;

	if (!attrs[MACSEC_ATTR_OFFLOAD])
		return -EINVAL;

	if (nla_parse_nested_deprecated(tb_offload, MACSEC_OFFLOAD_ATTR_MAX,
					attrs[MACSEC_ATTR_OFFLOAD],
					macsec_genl_offload_policy, NULL))
		return -EINVAL;

	rtnl_lock();

	dev = get_dev_from_nl(genl_info_net(info), attrs);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto out;
	}
	macsec = macsec_priv(dev);

	if (!tb_offload[MACSEC_OFFLOAD_ATTR_TYPE]) {
		ret = -EINVAL;
		goto out;
	}

	offload = nla_get_u8(tb_offload[MACSEC_OFFLOAD_ATTR_TYPE]);

	if (macsec->offload != offload)
		ret = macsec_update_offload(dev, offload);
out:
	rtnl_unlock();
	return ret;
}

static void get_tx_sa_stats(struct net_device *dev, int an,
			    struct macsec_tx_sa *tx_sa,
			    struct macsec_tx_sa_stats *sum)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	int cpu;

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (ops) {
			ctx.sa.assoc_num = an;
			ctx.sa.tx_sa = tx_sa;
			ctx.stats.tx_sa_stats = sum;
			ctx.secy = &macsec_priv(dev)->secy;
			macsec_offload(ops->mdo_get_tx_sa_stats, &ctx);
		}
		return;
	}

	for_each_possible_cpu(cpu) {
		const struct macsec_tx_sa_stats *stats =
			per_cpu_ptr(tx_sa->stats, cpu);

		sum->OutPktsProtected += stats->OutPktsProtected;
		sum->OutPktsEncrypted += stats->OutPktsEncrypted;
	}
}

static int copy_tx_sa_stats(struct sk_buff *skb, struct macsec_tx_sa_stats *sum)
{
	if (nla_put_u32(skb, MACSEC_SA_STATS_ATTR_OUT_PKTS_PROTECTED,
			sum->OutPktsProtected) ||
	    nla_put_u32(skb, MACSEC_SA_STATS_ATTR_OUT_PKTS_ENCRYPTED,
			sum->OutPktsEncrypted))
		return -EMSGSIZE;

	return 0;
}

static void get_rx_sa_stats(struct net_device *dev,
			    struct macsec_rx_sc *rx_sc, int an,
			    struct macsec_rx_sa *rx_sa,
			    struct macsec_rx_sa_stats *sum)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	int cpu;

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (ops) {
			ctx.sa.assoc_num = an;
			ctx.sa.rx_sa = rx_sa;
			ctx.stats.rx_sa_stats = sum;
			ctx.secy = &macsec_priv(dev)->secy;
			ctx.rx_sc = rx_sc;
			macsec_offload(ops->mdo_get_rx_sa_stats, &ctx);
		}
		return;
	}

	for_each_possible_cpu(cpu) {
		const struct macsec_rx_sa_stats *stats =
			per_cpu_ptr(rx_sa->stats, cpu);

		sum->InPktsOK         += stats->InPktsOK;
		sum->InPktsInvalid    += stats->InPktsInvalid;
		sum->InPktsNotValid   += stats->InPktsNotValid;
		sum->InPktsNotUsingSA += stats->InPktsNotUsingSA;
		sum->InPktsUnusedSA   += stats->InPktsUnusedSA;
	}
}

static int copy_rx_sa_stats(struct sk_buff *skb,
			    struct macsec_rx_sa_stats *sum)
{
	if (nla_put_u32(skb, MACSEC_SA_STATS_ATTR_IN_PKTS_OK, sum->InPktsOK) ||
	    nla_put_u32(skb, MACSEC_SA_STATS_ATTR_IN_PKTS_INVALID,
			sum->InPktsInvalid) ||
	    nla_put_u32(skb, MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_VALID,
			sum->InPktsNotValid) ||
	    nla_put_u32(skb, MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_USING_SA,
			sum->InPktsNotUsingSA) ||
	    nla_put_u32(skb, MACSEC_SA_STATS_ATTR_IN_PKTS_UNUSED_SA,
			sum->InPktsUnusedSA))
		return -EMSGSIZE;

	return 0;
}

static void get_rx_sc_stats(struct net_device *dev,
			    struct macsec_rx_sc *rx_sc,
			    struct macsec_rx_sc_stats *sum)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	int cpu;

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (ops) {
			ctx.stats.rx_sc_stats = sum;
			ctx.secy = &macsec_priv(dev)->secy;
			ctx.rx_sc = rx_sc;
			macsec_offload(ops->mdo_get_rx_sc_stats, &ctx);
		}
		return;
	}

	for_each_possible_cpu(cpu) {
		const struct pcpu_rx_sc_stats *stats;
		struct macsec_rx_sc_stats tmp;
		unsigned int start;

		stats = per_cpu_ptr(rx_sc->stats, cpu);
		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			memcpy(&tmp, &stats->stats, sizeof(tmp));
		} while (u64_stats_fetch_retry(&stats->syncp, start));

		sum->InOctetsValidated += tmp.InOctetsValidated;
		sum->InOctetsDecrypted += tmp.InOctetsDecrypted;
		sum->InPktsUnchecked   += tmp.InPktsUnchecked;
		sum->InPktsDelayed     += tmp.InPktsDelayed;
		sum->InPktsOK          += tmp.InPktsOK;
		sum->InPktsInvalid     += tmp.InPktsInvalid;
		sum->InPktsLate        += tmp.InPktsLate;
		sum->InPktsNotValid    += tmp.InPktsNotValid;
		sum->InPktsNotUsingSA  += tmp.InPktsNotUsingSA;
		sum->InPktsUnusedSA    += tmp.InPktsUnusedSA;
	}
}

static int copy_rx_sc_stats(struct sk_buff *skb, struct macsec_rx_sc_stats *sum)
{
	if (nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED,
			      sum->InOctetsValidated,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_OCTETS_DECRYPTED,
			      sum->InOctetsDecrypted,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNCHECKED,
			      sum->InPktsUnchecked,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_DELAYED,
			      sum->InPktsDelayed,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_OK,
			      sum->InPktsOK,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_INVALID,
			      sum->InPktsInvalid,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_LATE,
			      sum->InPktsLate,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_VALID,
			      sum->InPktsNotValid,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_USING_SA,
			      sum->InPktsNotUsingSA,
			      MACSEC_RXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNUSED_SA,
			      sum->InPktsUnusedSA,
			      MACSEC_RXSC_STATS_ATTR_PAD))
		return -EMSGSIZE;

	return 0;
}

static void get_tx_sc_stats(struct net_device *dev,
			    struct macsec_tx_sc_stats *sum)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	int cpu;

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (ops) {
			ctx.stats.tx_sc_stats = sum;
			ctx.secy = &macsec_priv(dev)->secy;
			macsec_offload(ops->mdo_get_tx_sc_stats, &ctx);
		}
		return;
	}

	for_each_possible_cpu(cpu) {
		const struct pcpu_tx_sc_stats *stats;
		struct macsec_tx_sc_stats tmp;
		unsigned int start;

		stats = per_cpu_ptr(macsec_priv(dev)->secy.tx_sc.stats, cpu);
		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			memcpy(&tmp, &stats->stats, sizeof(tmp));
		} while (u64_stats_fetch_retry(&stats->syncp, start));

		sum->OutPktsProtected   += tmp.OutPktsProtected;
		sum->OutPktsEncrypted   += tmp.OutPktsEncrypted;
		sum->OutOctetsProtected += tmp.OutOctetsProtected;
		sum->OutOctetsEncrypted += tmp.OutOctetsEncrypted;
	}
}

static int copy_tx_sc_stats(struct sk_buff *skb, struct macsec_tx_sc_stats *sum)
{
	if (nla_put_u64_64bit(skb, MACSEC_TXSC_STATS_ATTR_OUT_PKTS_PROTECTED,
			      sum->OutPktsProtected,
			      MACSEC_TXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_TXSC_STATS_ATTR_OUT_PKTS_ENCRYPTED,
			      sum->OutPktsEncrypted,
			      MACSEC_TXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_PROTECTED,
			      sum->OutOctetsProtected,
			      MACSEC_TXSC_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_ENCRYPTED,
			      sum->OutOctetsEncrypted,
			      MACSEC_TXSC_STATS_ATTR_PAD))
		return -EMSGSIZE;

	return 0;
}

static void get_secy_stats(struct net_device *dev, struct macsec_dev_stats *sum)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	int cpu;

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (ops) {
			ctx.stats.dev_stats = sum;
			ctx.secy = &macsec_priv(dev)->secy;
			macsec_offload(ops->mdo_get_dev_stats, &ctx);
		}
		return;
	}

	for_each_possible_cpu(cpu) {
		const struct pcpu_secy_stats *stats;
		struct macsec_dev_stats tmp;
		unsigned int start;

		stats = per_cpu_ptr(macsec_priv(dev)->stats, cpu);
		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			memcpy(&tmp, &stats->stats, sizeof(tmp));
		} while (u64_stats_fetch_retry(&stats->syncp, start));

		sum->OutPktsUntagged  += tmp.OutPktsUntagged;
		sum->InPktsUntagged   += tmp.InPktsUntagged;
		sum->OutPktsTooLong   += tmp.OutPktsTooLong;
		sum->InPktsNoTag      += tmp.InPktsNoTag;
		sum->InPktsBadTag     += tmp.InPktsBadTag;
		sum->InPktsUnknownSCI += tmp.InPktsUnknownSCI;
		sum->InPktsNoSCI      += tmp.InPktsNoSCI;
		sum->InPktsOverrun    += tmp.InPktsOverrun;
	}
}

static int copy_secy_stats(struct sk_buff *skb, struct macsec_dev_stats *sum)
{
	if (nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_OUT_PKTS_UNTAGGED,
			      sum->OutPktsUntagged,
			      MACSEC_SECY_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_IN_PKTS_UNTAGGED,
			      sum->InPktsUntagged,
			      MACSEC_SECY_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_OUT_PKTS_TOO_LONG,
			      sum->OutPktsTooLong,
			      MACSEC_SECY_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_TAG,
			      sum->InPktsNoTag,
			      MACSEC_SECY_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_IN_PKTS_BAD_TAG,
			      sum->InPktsBadTag,
			      MACSEC_SECY_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_IN_PKTS_UNKNOWN_SCI,
			      sum->InPktsUnknownSCI,
			      MACSEC_SECY_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_SCI,
			      sum->InPktsNoSCI,
			      MACSEC_SECY_STATS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_STATS_ATTR_IN_PKTS_OVERRUN,
			      sum->InPktsOverrun,
			      MACSEC_SECY_STATS_ATTR_PAD))
		return -EMSGSIZE;

	return 0;
}

static int nla_put_secy(struct macsec_secy *secy, struct sk_buff *skb)
{
	struct macsec_tx_sc *tx_sc = &secy->tx_sc;
	struct nlattr *secy_nest = nla_nest_start_noflag(skb,
							 MACSEC_ATTR_SECY);
	u64 csid;

	if (!secy_nest)
		return 1;

	switch (secy->key_len) {
	case MACSEC_GCM_AES_128_SAK_LEN:
		csid = secy->xpn ? MACSEC_CIPHER_ID_GCM_AES_XPN_128 : MACSEC_DEFAULT_CIPHER_ID;
		break;
	case MACSEC_GCM_AES_256_SAK_LEN:
		csid = secy->xpn ? MACSEC_CIPHER_ID_GCM_AES_XPN_256 : MACSEC_CIPHER_ID_GCM_AES_256;
		break;
	default:
		goto cancel;
	}

	if (nla_put_sci(skb, MACSEC_SECY_ATTR_SCI, secy->sci,
			MACSEC_SECY_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, MACSEC_SECY_ATTR_CIPHER_SUITE,
			      csid, MACSEC_SECY_ATTR_PAD) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_ICV_LEN, secy->icv_len) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_OPER, secy->operational) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_PROTECT, secy->protect_frames) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_REPLAY, secy->replay_protect) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_VALIDATE, secy->validate_frames) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_ENCRYPT, tx_sc->encrypt) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_INC_SCI, tx_sc->send_sci) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_ES, tx_sc->end_station) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_SCB, tx_sc->scb) ||
	    nla_put_u8(skb, MACSEC_SECY_ATTR_ENCODING_SA, tx_sc->encoding_sa))
		goto cancel;

	if (secy->replay_protect) {
		if (nla_put_u32(skb, MACSEC_SECY_ATTR_WINDOW, secy->replay_window))
			goto cancel;
	}

	nla_nest_end(skb, secy_nest);
	return 0;

cancel:
	nla_nest_cancel(skb, secy_nest);
	return 1;
}

static noinline_for_stack int
dump_secy(struct macsec_secy *secy, struct net_device *dev,
	  struct sk_buff *skb, struct netlink_callback *cb)
{
	struct macsec_tx_sc_stats tx_sc_stats = {0, };
	struct macsec_tx_sa_stats tx_sa_stats = {0, };
	struct macsec_rx_sc_stats rx_sc_stats = {0, };
	struct macsec_rx_sa_stats rx_sa_stats = {0, };
	struct macsec_dev *macsec = netdev_priv(dev);
	struct macsec_dev_stats dev_stats = {0, };
	struct macsec_tx_sc *tx_sc = &secy->tx_sc;
	struct nlattr *txsa_list, *rxsc_list;
	struct macsec_rx_sc *rx_sc;
	struct nlattr *attr;
	void *hdr;
	int i, j;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &macsec_fam, NLM_F_MULTI, MACSEC_CMD_GET_TXSC);
	if (!hdr)
		return -EMSGSIZE;

	genl_dump_check_consistent(cb, hdr);

	if (nla_put_u32(skb, MACSEC_ATTR_IFINDEX, dev->ifindex))
		goto nla_put_failure;

	attr = nla_nest_start_noflag(skb, MACSEC_ATTR_OFFLOAD);
	if (!attr)
		goto nla_put_failure;
	if (nla_put_u8(skb, MACSEC_OFFLOAD_ATTR_TYPE, macsec->offload))
		goto nla_put_failure;
	nla_nest_end(skb, attr);

	if (nla_put_secy(secy, skb))
		goto nla_put_failure;

	attr = nla_nest_start_noflag(skb, MACSEC_ATTR_TXSC_STATS);
	if (!attr)
		goto nla_put_failure;

	get_tx_sc_stats(dev, &tx_sc_stats);
	if (copy_tx_sc_stats(skb, &tx_sc_stats)) {
		nla_nest_cancel(skb, attr);
		goto nla_put_failure;
	}
	nla_nest_end(skb, attr);

	attr = nla_nest_start_noflag(skb, MACSEC_ATTR_SECY_STATS);
	if (!attr)
		goto nla_put_failure;
	get_secy_stats(dev, &dev_stats);
	if (copy_secy_stats(skb, &dev_stats)) {
		nla_nest_cancel(skb, attr);
		goto nla_put_failure;
	}
	nla_nest_end(skb, attr);

	txsa_list = nla_nest_start_noflag(skb, MACSEC_ATTR_TXSA_LIST);
	if (!txsa_list)
		goto nla_put_failure;
	for (i = 0, j = 1; i < MACSEC_NUM_AN; i++) {
		struct macsec_tx_sa *tx_sa = rtnl_dereference(tx_sc->sa[i]);
		struct nlattr *txsa_nest;
		u64 pn;
		int pn_len;

		if (!tx_sa)
			continue;

		txsa_nest = nla_nest_start_noflag(skb, j++);
		if (!txsa_nest) {
			nla_nest_cancel(skb, txsa_list);
			goto nla_put_failure;
		}

		attr = nla_nest_start_noflag(skb, MACSEC_SA_ATTR_STATS);
		if (!attr) {
			nla_nest_cancel(skb, txsa_nest);
			nla_nest_cancel(skb, txsa_list);
			goto nla_put_failure;
		}
		memset(&tx_sa_stats, 0, sizeof(tx_sa_stats));
		get_tx_sa_stats(dev, i, tx_sa, &tx_sa_stats);
		if (copy_tx_sa_stats(skb, &tx_sa_stats)) {
			nla_nest_cancel(skb, attr);
			nla_nest_cancel(skb, txsa_nest);
			nla_nest_cancel(skb, txsa_list);
			goto nla_put_failure;
		}
		nla_nest_end(skb, attr);

		if (secy->xpn) {
			pn = tx_sa->next_pn;
			pn_len = MACSEC_XPN_PN_LEN;
		} else {
			pn = tx_sa->next_pn_halves.lower;
			pn_len = MACSEC_DEFAULT_PN_LEN;
		}

		if (nla_put_u8(skb, MACSEC_SA_ATTR_AN, i) ||
		    nla_put(skb, MACSEC_SA_ATTR_PN, pn_len, &pn) ||
		    nla_put(skb, MACSEC_SA_ATTR_KEYID, MACSEC_KEYID_LEN, tx_sa->key.id) ||
		    (secy->xpn && nla_put_ssci(skb, MACSEC_SA_ATTR_SSCI, tx_sa->ssci)) ||
		    nla_put_u8(skb, MACSEC_SA_ATTR_ACTIVE, tx_sa->active)) {
			nla_nest_cancel(skb, txsa_nest);
			nla_nest_cancel(skb, txsa_list);
			goto nla_put_failure;
		}

		nla_nest_end(skb, txsa_nest);
	}
	nla_nest_end(skb, txsa_list);

	rxsc_list = nla_nest_start_noflag(skb, MACSEC_ATTR_RXSC_LIST);
	if (!rxsc_list)
		goto nla_put_failure;

	j = 1;
	for_each_rxsc_rtnl(secy, rx_sc) {
		int k;
		struct nlattr *rxsa_list;
		struct nlattr *rxsc_nest = nla_nest_start_noflag(skb, j++);

		if (!rxsc_nest) {
			nla_nest_cancel(skb, rxsc_list);
			goto nla_put_failure;
		}

		if (nla_put_u8(skb, MACSEC_RXSC_ATTR_ACTIVE, rx_sc->active) ||
		    nla_put_sci(skb, MACSEC_RXSC_ATTR_SCI, rx_sc->sci,
				MACSEC_RXSC_ATTR_PAD)) {
			nla_nest_cancel(skb, rxsc_nest);
			nla_nest_cancel(skb, rxsc_list);
			goto nla_put_failure;
		}

		attr = nla_nest_start_noflag(skb, MACSEC_RXSC_ATTR_STATS);
		if (!attr) {
			nla_nest_cancel(skb, rxsc_nest);
			nla_nest_cancel(skb, rxsc_list);
			goto nla_put_failure;
		}
		memset(&rx_sc_stats, 0, sizeof(rx_sc_stats));
		get_rx_sc_stats(dev, rx_sc, &rx_sc_stats);
		if (copy_rx_sc_stats(skb, &rx_sc_stats)) {
			nla_nest_cancel(skb, attr);
			nla_nest_cancel(skb, rxsc_nest);
			nla_nest_cancel(skb, rxsc_list);
			goto nla_put_failure;
		}
		nla_nest_end(skb, attr);

		rxsa_list = nla_nest_start_noflag(skb,
						  MACSEC_RXSC_ATTR_SA_LIST);
		if (!rxsa_list) {
			nla_nest_cancel(skb, rxsc_nest);
			nla_nest_cancel(skb, rxsc_list);
			goto nla_put_failure;
		}

		for (i = 0, k = 1; i < MACSEC_NUM_AN; i++) {
			struct macsec_rx_sa *rx_sa = rtnl_dereference(rx_sc->sa[i]);
			struct nlattr *rxsa_nest;
			u64 pn;
			int pn_len;

			if (!rx_sa)
				continue;

			rxsa_nest = nla_nest_start_noflag(skb, k++);
			if (!rxsa_nest) {
				nla_nest_cancel(skb, rxsa_list);
				nla_nest_cancel(skb, rxsc_nest);
				nla_nest_cancel(skb, rxsc_list);
				goto nla_put_failure;
			}

			attr = nla_nest_start_noflag(skb,
						     MACSEC_SA_ATTR_STATS);
			if (!attr) {
				nla_nest_cancel(skb, rxsa_list);
				nla_nest_cancel(skb, rxsc_nest);
				nla_nest_cancel(skb, rxsc_list);
				goto nla_put_failure;
			}
			memset(&rx_sa_stats, 0, sizeof(rx_sa_stats));
			get_rx_sa_stats(dev, rx_sc, i, rx_sa, &rx_sa_stats);
			if (copy_rx_sa_stats(skb, &rx_sa_stats)) {
				nla_nest_cancel(skb, attr);
				nla_nest_cancel(skb, rxsa_list);
				nla_nest_cancel(skb, rxsc_nest);
				nla_nest_cancel(skb, rxsc_list);
				goto nla_put_failure;
			}
			nla_nest_end(skb, attr);

			if (secy->xpn) {
				pn = rx_sa->next_pn;
				pn_len = MACSEC_XPN_PN_LEN;
			} else {
				pn = rx_sa->next_pn_halves.lower;
				pn_len = MACSEC_DEFAULT_PN_LEN;
			}

			if (nla_put_u8(skb, MACSEC_SA_ATTR_AN, i) ||
			    nla_put(skb, MACSEC_SA_ATTR_PN, pn_len, &pn) ||
			    nla_put(skb, MACSEC_SA_ATTR_KEYID, MACSEC_KEYID_LEN, rx_sa->key.id) ||
			    (secy->xpn && nla_put_ssci(skb, MACSEC_SA_ATTR_SSCI, rx_sa->ssci)) ||
			    nla_put_u8(skb, MACSEC_SA_ATTR_ACTIVE, rx_sa->active)) {
				nla_nest_cancel(skb, rxsa_nest);
				nla_nest_cancel(skb, rxsc_nest);
				nla_nest_cancel(skb, rxsc_list);
				goto nla_put_failure;
			}
			nla_nest_end(skb, rxsa_nest);
		}

		nla_nest_end(skb, rxsa_list);
		nla_nest_end(skb, rxsc_nest);
	}

	nla_nest_end(skb, rxsc_list);

	genlmsg_end(skb, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int macsec_generation = 1; /* protected by RTNL */

static int macsec_dump_txsc(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;
	int dev_idx, d;

	dev_idx = cb->args[0];

	d = 0;
	rtnl_lock();

	cb->seq = macsec_generation;

	for_each_netdev(net, dev) {
		struct macsec_secy *secy;

		if (d < dev_idx)
			goto next;

		if (!netif_is_macsec(dev))
			goto next;

		secy = &macsec_priv(dev)->secy;
		if (dump_secy(secy, dev, skb, cb) < 0)
			goto done;
next:
		d++;
	}

done:
	rtnl_unlock();
	cb->args[0] = d;
	return skb->len;
}

static const struct genl_small_ops macsec_genl_ops[] = {
	{
		.cmd = MACSEC_CMD_GET_TXSC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.dumpit = macsec_dump_txsc,
	},
	{
		.cmd = MACSEC_CMD_ADD_RXSC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_add_rxsc,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_DEL_RXSC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_del_rxsc,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_UPD_RXSC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_upd_rxsc,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_ADD_TXSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_add_txsa,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_DEL_TXSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_del_txsa,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_UPD_TXSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_upd_txsa,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_ADD_RXSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_add_rxsa,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_DEL_RXSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_del_rxsa,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_UPD_RXSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_upd_rxsa,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MACSEC_CMD_UPD_OFFLOAD,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = macsec_upd_offload,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family macsec_fam __ro_after_init = {
	.name		= MACSEC_GENL_NAME,
	.hdrsize	= 0,
	.version	= MACSEC_GENL_VERSION,
	.maxattr	= MACSEC_ATTR_MAX,
	.policy = macsec_genl_policy,
	.netnsok	= true,
	.module		= THIS_MODULE,
	.small_ops	= macsec_genl_ops,
	.n_small_ops	= ARRAY_SIZE(macsec_genl_ops),
	.resv_start_op	= MACSEC_CMD_UPD_OFFLOAD + 1,
};

static struct sk_buff *macsec_insert_tx_tag(struct sk_buff *skb,
					    struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	const struct macsec_ops *ops;
	struct phy_device *phydev;
	struct macsec_context ctx;
	int skb_final_len;
	int err;

	ops = macsec_get_ops(macsec, &ctx);
	skb_final_len = skb->len - ETH_HLEN + ops->needed_headroom +
		ops->needed_tailroom;
	if (unlikely(skb_final_len > macsec->real_dev->mtu)) {
		err = -EINVAL;
		goto cleanup;
	}

	phydev = macsec->real_dev->phydev;

	err = skb_ensure_writable_head_tail(skb, dev);
	if (unlikely(err < 0))
		goto cleanup;

	err = ops->mdo_insert_tx_tag(phydev, skb);
	if (unlikely(err))
		goto cleanup;

	return skb;
cleanup:
	kfree_skb(skb);
	return ERR_PTR(err);
}

static netdev_tx_t macsec_start_xmit(struct sk_buff *skb,
				     struct net_device *dev)
{
	struct macsec_dev *macsec = netdev_priv(dev);
	struct macsec_secy *secy = &macsec->secy;
	struct pcpu_secy_stats *secy_stats;
	int ret, len;

	if (macsec_is_offloaded(netdev_priv(dev))) {
		struct metadata_dst *md_dst = secy->tx_sc.md_dst;

		skb_dst_drop(skb);
		dst_hold(&md_dst->dst);
		skb_dst_set(skb, &md_dst->dst);

		if (macsec->insert_tx_tag) {
			skb = macsec_insert_tx_tag(skb, dev);
			if (IS_ERR(skb)) {
				DEV_STATS_INC(dev, tx_dropped);
				return NETDEV_TX_OK;
			}
		}

		skb->dev = macsec->real_dev;
		return dev_queue_xmit(skb);
	}

	/* 10.5 */
	if (!secy->protect_frames) {
		secy_stats = this_cpu_ptr(macsec->stats);
		u64_stats_update_begin(&secy_stats->syncp);
		secy_stats->stats.OutPktsUntagged++;
		u64_stats_update_end(&secy_stats->syncp);
		skb->dev = macsec->real_dev;
		len = skb->len;
		ret = dev_queue_xmit(skb);
		count_tx(dev, ret, len);
		return ret;
	}

	if (!secy->operational) {
		kfree_skb(skb);
		DEV_STATS_INC(dev, tx_dropped);
		return NETDEV_TX_OK;
	}

	len = skb->len;
	skb = macsec_encrypt(skb, dev);
	if (IS_ERR(skb)) {
		if (PTR_ERR(skb) != -EINPROGRESS)
			DEV_STATS_INC(dev, tx_dropped);
		return NETDEV_TX_OK;
	}

	macsec_count_tx(skb, &macsec->secy.tx_sc, macsec_skb_cb(skb)->tx_sa);

	macsec_encrypt_finish(skb, dev);
	ret = dev_queue_xmit(skb);
	count_tx(dev, ret, len);
	return ret;
}

#define MACSEC_FEATURES \
	(NETIF_F_SG | NETIF_F_HIGHDMA | NETIF_F_FRAGLIST)

static int macsec_dev_init(struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;
	int err;

	err = gro_cells_init(&macsec->gro_cells, dev);
	if (err)
		return err;

	dev->features = real_dev->features & MACSEC_FEATURES;
	dev->features |= NETIF_F_GSO_SOFTWARE;
	dev->lltx = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;

	macsec_set_head_tail_room(dev);

	if (is_zero_ether_addr(dev->dev_addr))
		eth_hw_addr_inherit(dev, real_dev);
	if (is_zero_ether_addr(dev->broadcast))
		memcpy(dev->broadcast, real_dev->broadcast, dev->addr_len);

	/* Get macsec's reference to real_dev */
	netdev_hold(real_dev, &macsec->dev_tracker, GFP_KERNEL);

	return 0;
}

static void macsec_dev_uninit(struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);

	gro_cells_destroy(&macsec->gro_cells);
}

static netdev_features_t macsec_fix_features(struct net_device *dev,
					     netdev_features_t features)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;

	features &= (real_dev->features & MACSEC_FEATURES) |
		    NETIF_F_GSO_SOFTWARE | NETIF_F_SOFT_FEATURES;

	return features;
}

static int macsec_dev_open(struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;
	int err;

	err = dev_uc_add(real_dev, dev->dev_addr);
	if (err < 0)
		return err;

	if (dev->flags & IFF_ALLMULTI) {
		err = dev_set_allmulti(real_dev, 1);
		if (err < 0)
			goto del_unicast;
	}

	if (dev->flags & IFF_PROMISC) {
		err = dev_set_promiscuity(real_dev, 1);
		if (err < 0)
			goto clear_allmulti;
	}

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(netdev_priv(dev), &ctx);
		if (!ops) {
			err = -EOPNOTSUPP;
			goto clear_allmulti;
		}

		ctx.secy = &macsec->secy;
		err = macsec_offload(ops->mdo_dev_open, &ctx);
		if (err)
			goto clear_allmulti;
	}

	if (netif_carrier_ok(real_dev))
		netif_carrier_on(dev);

	return 0;
clear_allmulti:
	if (dev->flags & IFF_ALLMULTI)
		dev_set_allmulti(real_dev, -1);
del_unicast:
	dev_uc_del(real_dev, dev->dev_addr);
	netif_carrier_off(dev);
	return err;
}

static int macsec_dev_stop(struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;

	netif_carrier_off(dev);

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (ops) {
			ctx.secy = &macsec->secy;
			macsec_offload(ops->mdo_dev_stop, &ctx);
		}
	}

	dev_mc_unsync(real_dev, dev);
	dev_uc_unsync(real_dev, dev);

	if (dev->flags & IFF_ALLMULTI)
		dev_set_allmulti(real_dev, -1);

	if (dev->flags & IFF_PROMISC)
		dev_set_promiscuity(real_dev, -1);

	dev_uc_del(real_dev, dev->dev_addr);

	return 0;
}

static void macsec_dev_change_rx_flags(struct net_device *dev, int change)
{
	struct net_device *real_dev = macsec_priv(dev)->real_dev;

	if (!(dev->flags & IFF_UP))
		return;

	if (change & IFF_ALLMULTI)
		dev_set_allmulti(real_dev, dev->flags & IFF_ALLMULTI ? 1 : -1);

	if (change & IFF_PROMISC)
		dev_set_promiscuity(real_dev,
				    dev->flags & IFF_PROMISC ? 1 : -1);
}

static void macsec_dev_set_rx_mode(struct net_device *dev)
{
	struct net_device *real_dev = macsec_priv(dev)->real_dev;

	dev_mc_sync(real_dev, dev);
	dev_uc_sync(real_dev, dev);
}

static int macsec_set_mac_address(struct net_device *dev, void *p)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;
	struct sockaddr *addr = p;
	u8  old_addr[ETH_ALEN];
	int err;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	if (dev->flags & IFF_UP) {
		err = dev_uc_add(real_dev, addr->sa_data);
		if (err < 0)
			return err;
	}

	ether_addr_copy(old_addr, dev->dev_addr);
	eth_hw_addr_set(dev, addr->sa_data);

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (!ops) {
			err = -EOPNOTSUPP;
			goto restore_old_addr;
		}

		ctx.secy = &macsec->secy;
		err = macsec_offload(ops->mdo_upd_secy, &ctx);
		if (err)
			goto restore_old_addr;
	}

	if (dev->flags & IFF_UP)
		dev_uc_del(real_dev, old_addr);

	return 0;

restore_old_addr:
	if (dev->flags & IFF_UP)
		dev_uc_del(real_dev, addr->sa_data);

	eth_hw_addr_set(dev, old_addr);

	return err;
}

static int macsec_change_mtu(struct net_device *dev, int new_mtu)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	unsigned int extra = macsec->secy.icv_len + macsec_extra_len(true);

	if (macsec->real_dev->mtu - extra < new_mtu)
		return -ERANGE;

	WRITE_ONCE(dev->mtu, new_mtu);

	return 0;
}

static void macsec_get_stats64(struct net_device *dev,
			       struct rtnl_link_stats64 *s)
{
	if (!dev->tstats)
		return;

	dev_fetch_sw_netstats(s, dev->tstats);

	s->rx_dropped = DEV_STATS_READ(dev, rx_dropped);
	s->tx_dropped = DEV_STATS_READ(dev, tx_dropped);
	s->rx_errors = DEV_STATS_READ(dev, rx_errors);
}

static int macsec_get_iflink(const struct net_device *dev)
{
	return READ_ONCE(macsec_priv(dev)->real_dev->ifindex);
}

static const struct net_device_ops macsec_netdev_ops = {
	.ndo_init		= macsec_dev_init,
	.ndo_uninit		= macsec_dev_uninit,
	.ndo_open		= macsec_dev_open,
	.ndo_stop		= macsec_dev_stop,
	.ndo_fix_features	= macsec_fix_features,
	.ndo_change_mtu		= macsec_change_mtu,
	.ndo_set_rx_mode	= macsec_dev_set_rx_mode,
	.ndo_change_rx_flags	= macsec_dev_change_rx_flags,
	.ndo_set_mac_address	= macsec_set_mac_address,
	.ndo_start_xmit		= macsec_start_xmit,
	.ndo_get_stats64	= macsec_get_stats64,
	.ndo_get_iflink		= macsec_get_iflink,
};

static const struct device_type macsec_type = {
	.name = "macsec",
};

static const struct nla_policy macsec_rtnl_policy[IFLA_MACSEC_MAX + 1] = {
	[IFLA_MACSEC_SCI] = { .type = NLA_U64 },
	[IFLA_MACSEC_PORT] = { .type = NLA_U16 },
	[IFLA_MACSEC_ICV_LEN] = { .type = NLA_U8 },
	[IFLA_MACSEC_CIPHER_SUITE] = { .type = NLA_U64 },
	[IFLA_MACSEC_WINDOW] = { .type = NLA_U32 },
	[IFLA_MACSEC_ENCODING_SA] = { .type = NLA_U8 },
	[IFLA_MACSEC_ENCRYPT] = { .type = NLA_U8 },
	[IFLA_MACSEC_PROTECT] = { .type = NLA_U8 },
	[IFLA_MACSEC_INC_SCI] = { .type = NLA_U8 },
	[IFLA_MACSEC_ES] = { .type = NLA_U8 },
	[IFLA_MACSEC_SCB] = { .type = NLA_U8 },
	[IFLA_MACSEC_REPLAY_PROTECT] = { .type = NLA_U8 },
	[IFLA_MACSEC_VALIDATION] = { .type = NLA_U8 },
	[IFLA_MACSEC_OFFLOAD] = { .type = NLA_U8 },
};

static void macsec_free_netdev(struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);

	if (macsec->secy.tx_sc.md_dst)
		metadata_dst_free(macsec->secy.tx_sc.md_dst);
	free_percpu(macsec->stats);
	free_percpu(macsec->secy.tx_sc.stats);

	/* Get rid of the macsec's reference to real_dev */
	netdev_put(macsec->real_dev, &macsec->dev_tracker);
}

static void macsec_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->min_mtu = 0;
	dev->max_mtu = ETH_MAX_MTU;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->netdev_ops = &macsec_netdev_ops;
	dev->needs_free_netdev = true;
	dev->priv_destructor = macsec_free_netdev;
	SET_NETDEV_DEVTYPE(dev, &macsec_type);

	eth_zero_addr(dev->broadcast);
}

static int macsec_changelink_common(struct net_device *dev,
				    struct nlattr *data[])
{
	struct macsec_secy *secy;
	struct macsec_tx_sc *tx_sc;

	secy = &macsec_priv(dev)->secy;
	tx_sc = &secy->tx_sc;

	if (data[IFLA_MACSEC_ENCODING_SA]) {
		struct macsec_tx_sa *tx_sa;

		tx_sc->encoding_sa = nla_get_u8(data[IFLA_MACSEC_ENCODING_SA]);
		tx_sa = rtnl_dereference(tx_sc->sa[tx_sc->encoding_sa]);

		secy->operational = tx_sa && tx_sa->active;
	}

	if (data[IFLA_MACSEC_ENCRYPT])
		tx_sc->encrypt = !!nla_get_u8(data[IFLA_MACSEC_ENCRYPT]);

	if (data[IFLA_MACSEC_PROTECT])
		secy->protect_frames = !!nla_get_u8(data[IFLA_MACSEC_PROTECT]);

	if (data[IFLA_MACSEC_INC_SCI])
		tx_sc->send_sci = !!nla_get_u8(data[IFLA_MACSEC_INC_SCI]);

	if (data[IFLA_MACSEC_ES])
		tx_sc->end_station = !!nla_get_u8(data[IFLA_MACSEC_ES]);

	if (data[IFLA_MACSEC_SCB])
		tx_sc->scb = !!nla_get_u8(data[IFLA_MACSEC_SCB]);

	if (data[IFLA_MACSEC_REPLAY_PROTECT])
		secy->replay_protect = !!nla_get_u8(data[IFLA_MACSEC_REPLAY_PROTECT]);

	if (data[IFLA_MACSEC_VALIDATION])
		secy->validate_frames = nla_get_u8(data[IFLA_MACSEC_VALIDATION]);

	if (data[IFLA_MACSEC_CIPHER_SUITE]) {
		switch (nla_get_u64(data[IFLA_MACSEC_CIPHER_SUITE])) {
		case MACSEC_CIPHER_ID_GCM_AES_128:
		case MACSEC_DEFAULT_CIPHER_ID:
			secy->key_len = MACSEC_GCM_AES_128_SAK_LEN;
			secy->xpn = false;
			break;
		case MACSEC_CIPHER_ID_GCM_AES_256:
			secy->key_len = MACSEC_GCM_AES_256_SAK_LEN;
			secy->xpn = false;
			break;
		case MACSEC_CIPHER_ID_GCM_AES_XPN_128:
			secy->key_len = MACSEC_GCM_AES_128_SAK_LEN;
			secy->xpn = true;
			break;
		case MACSEC_CIPHER_ID_GCM_AES_XPN_256:
			secy->key_len = MACSEC_GCM_AES_256_SAK_LEN;
			secy->xpn = true;
			break;
		default:
			return -EINVAL;
		}
	}

	if (data[IFLA_MACSEC_WINDOW]) {
		secy->replay_window = nla_get_u32(data[IFLA_MACSEC_WINDOW]);

		/* IEEE 802.1AEbw-2013 10.7.8 - maximum replay window
		 * for XPN cipher suites */
		if (secy->xpn &&
		    secy->replay_window > MACSEC_XPN_MAX_REPLAY_WINDOW)
			return -EINVAL;
	}

	return 0;
}

static int macsec_changelink(struct net_device *dev, struct nlattr *tb[],
			     struct nlattr *data[],
			     struct netlink_ext_ack *extack)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	bool macsec_offload_state_change = false;
	enum macsec_offload offload;
	struct macsec_tx_sc tx_sc;
	struct macsec_secy secy;
	int ret;

	if (!data)
		return 0;

	if (data[IFLA_MACSEC_CIPHER_SUITE] ||
	    data[IFLA_MACSEC_ICV_LEN] ||
	    data[IFLA_MACSEC_SCI] ||
	    data[IFLA_MACSEC_PORT])
		return -EINVAL;

	/* Keep a copy of unmodified secy and tx_sc, in case the offload
	 * propagation fails, to revert macsec_changelink_common.
	 */
	memcpy(&secy, &macsec->secy, sizeof(secy));
	memcpy(&tx_sc, &macsec->secy.tx_sc, sizeof(tx_sc));

	ret = macsec_changelink_common(dev, data);
	if (ret)
		goto cleanup;

	if (data[IFLA_MACSEC_OFFLOAD]) {
		offload = nla_get_u8(data[IFLA_MACSEC_OFFLOAD]);
		if (macsec->offload != offload) {
			macsec_offload_state_change = true;
			ret = macsec_update_offload(dev, offload);
			if (ret)
				goto cleanup;
		}
	}

	/* If h/w offloading is available, propagate to the device */
	if (!macsec_offload_state_change && macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(netdev_priv(dev), &ctx);
		if (!ops) {
			ret = -EOPNOTSUPP;
			goto cleanup;
		}

		ctx.secy = &macsec->secy;
		ret = macsec_offload(ops->mdo_upd_secy, &ctx);
		if (ret)
			goto cleanup;
	}

	return 0;

cleanup:
	memcpy(&macsec->secy.tx_sc, &tx_sc, sizeof(tx_sc));
	memcpy(&macsec->secy, &secy, sizeof(secy));

	return ret;
}

static void macsec_del_dev(struct macsec_dev *macsec)
{
	int i;

	while (macsec->secy.rx_sc) {
		struct macsec_rx_sc *rx_sc = rtnl_dereference(macsec->secy.rx_sc);

		rcu_assign_pointer(macsec->secy.rx_sc, rx_sc->next);
		free_rx_sc(rx_sc);
	}

	for (i = 0; i < MACSEC_NUM_AN; i++) {
		struct macsec_tx_sa *sa = rtnl_dereference(macsec->secy.tx_sc.sa[i]);

		if (sa) {
			RCU_INIT_POINTER(macsec->secy.tx_sc.sa[i], NULL);
			clear_tx_sa(sa);
		}
	}
}

static void macsec_common_dellink(struct net_device *dev, struct list_head *head)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(netdev_priv(dev), &ctx);
		if (ops) {
			ctx.secy = &macsec->secy;
			macsec_offload(ops->mdo_del_secy, &ctx);
		}
	}

	unregister_netdevice_queue(dev, head);
	list_del_rcu(&macsec->secys);
	macsec_del_dev(macsec);
	netdev_upper_dev_unlink(real_dev, dev);

	macsec_generation++;
}

static void macsec_dellink(struct net_device *dev, struct list_head *head)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct net_device *real_dev = macsec->real_dev;
	struct macsec_rxh_data *rxd = macsec_data_rtnl(real_dev);

	macsec_common_dellink(dev, head);

	if (list_empty(&rxd->secys)) {
		netdev_rx_handler_unregister(real_dev);
		kfree(rxd);
	}
}

static int register_macsec_dev(struct net_device *real_dev,
			       struct net_device *dev)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct macsec_rxh_data *rxd = macsec_data_rtnl(real_dev);

	if (!rxd) {
		int err;

		rxd = kmalloc(sizeof(*rxd), GFP_KERNEL);
		if (!rxd)
			return -ENOMEM;

		INIT_LIST_HEAD(&rxd->secys);

		err = netdev_rx_handler_register(real_dev, macsec_handle_frame,
						 rxd);
		if (err < 0) {
			kfree(rxd);
			return err;
		}
	}

	list_add_tail_rcu(&macsec->secys, &rxd->secys);
	return 0;
}

static bool sci_exists(struct net_device *dev, sci_t sci)
{
	struct macsec_rxh_data *rxd = macsec_data_rtnl(dev);
	struct macsec_dev *macsec;

	list_for_each_entry(macsec, &rxd->secys, secys) {
		if (macsec->secy.sci == sci)
			return true;
	}

	return false;
}

static sci_t dev_to_sci(struct net_device *dev, __be16 port)
{
	return make_sci(dev->dev_addr, port);
}

static int macsec_add_dev(struct net_device *dev, sci_t sci, u8 icv_len)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	struct macsec_secy *secy = &macsec->secy;

	macsec->stats = netdev_alloc_pcpu_stats(struct pcpu_secy_stats);
	if (!macsec->stats)
		return -ENOMEM;

	secy->tx_sc.stats = netdev_alloc_pcpu_stats(struct pcpu_tx_sc_stats);
	if (!secy->tx_sc.stats)
		return -ENOMEM;

	secy->tx_sc.md_dst = metadata_dst_alloc(0, METADATA_MACSEC, GFP_KERNEL);
	if (!secy->tx_sc.md_dst)
		/* macsec and secy percpu stats will be freed when unregistering
		 * net_device in macsec_free_netdev()
		 */
		return -ENOMEM;

	if (sci == MACSEC_UNDEF_SCI)
		sci = dev_to_sci(dev, MACSEC_PORT_ES);

	secy->netdev = dev;
	secy->operational = true;
	secy->key_len = DEFAULT_SAK_LEN;
	secy->icv_len = icv_len;
	secy->validate_frames = MACSEC_VALIDATE_DEFAULT;
	secy->protect_frames = true;
	secy->replay_protect = false;
	secy->xpn = DEFAULT_XPN;

	secy->sci = sci;
	secy->tx_sc.md_dst->u.macsec_info.sci = sci;
	secy->tx_sc.active = true;
	secy->tx_sc.encoding_sa = DEFAULT_ENCODING_SA;
	secy->tx_sc.encrypt = DEFAULT_ENCRYPT;
	secy->tx_sc.send_sci = DEFAULT_SEND_SCI;
	secy->tx_sc.end_station = false;
	secy->tx_sc.scb = false;

	return 0;
}

static struct lock_class_key macsec_netdev_addr_lock_key;

static int macsec_newlink(struct net *net, struct net_device *dev,
			  struct nlattr *tb[], struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	struct macsec_dev *macsec = macsec_priv(dev);
	rx_handler_func_t *rx_handler;
	u8 icv_len = MACSEC_DEFAULT_ICV_LEN;
	struct net_device *real_dev;
	int err, mtu;
	sci_t sci;

	if (!tb[IFLA_LINK])
		return -EINVAL;
	real_dev = __dev_get_by_index(net, nla_get_u32(tb[IFLA_LINK]));
	if (!real_dev)
		return -ENODEV;
	if (real_dev->type != ARPHRD_ETHER)
		return -EINVAL;

	dev->priv_flags |= IFF_MACSEC;

	macsec->real_dev = real_dev;

	if (data && data[IFLA_MACSEC_OFFLOAD])
		macsec->offload = nla_get_offload(data[IFLA_MACSEC_OFFLOAD]);
	else
		/* MACsec offloading is off by default */
		macsec->offload = MACSEC_OFFLOAD_OFF;

	/* Check if the offloading mode is supported by the underlying layers */
	if (macsec->offload != MACSEC_OFFLOAD_OFF &&
	    !macsec_check_offload(macsec->offload, macsec))
		return -EOPNOTSUPP;

	/* send_sci must be set to true when transmit sci explicitly is set */
	if ((data && data[IFLA_MACSEC_SCI]) &&
	    (data && data[IFLA_MACSEC_INC_SCI])) {
		u8 send_sci = !!nla_get_u8(data[IFLA_MACSEC_INC_SCI]);

		if (!send_sci)
			return -EINVAL;
	}

	if (data && data[IFLA_MACSEC_ICV_LEN])
		icv_len = nla_get_u8(data[IFLA_MACSEC_ICV_LEN]);
	mtu = real_dev->mtu - icv_len - macsec_extra_len(true);
	if (mtu < 0)
		dev->mtu = 0;
	else
		dev->mtu = mtu;

	rx_handler = rtnl_dereference(real_dev->rx_handler);
	if (rx_handler && rx_handler != macsec_handle_frame)
		return -EBUSY;

	err = register_netdevice(dev);
	if (err < 0)
		return err;

	netdev_lockdep_set_classes(dev);
	lockdep_set_class(&dev->addr_list_lock,
			  &macsec_netdev_addr_lock_key);

	err = netdev_upper_dev_link(real_dev, dev, extack);
	if (err < 0)
		goto unregister;

	/* need to be already registered so that ->init has run and
	 * the MAC addr is set
	 */
	if (data && data[IFLA_MACSEC_SCI])
		sci = nla_get_sci(data[IFLA_MACSEC_SCI]);
	else if (data && data[IFLA_MACSEC_PORT])
		sci = dev_to_sci(dev, nla_get_be16(data[IFLA_MACSEC_PORT]));
	else
		sci = dev_to_sci(dev, MACSEC_PORT_ES);

	if (rx_handler && sci_exists(real_dev, sci)) {
		err = -EBUSY;
		goto unlink;
	}

	err = macsec_add_dev(dev, sci, icv_len);
	if (err)
		goto unlink;

	if (data) {
		err = macsec_changelink_common(dev, data);
		if (err)
			goto del_dev;
	}

	/* If h/w offloading is available, propagate to the device */
	if (macsec_is_offloaded(macsec)) {
		const struct macsec_ops *ops;
		struct macsec_context ctx;

		ops = macsec_get_ops(macsec, &ctx);
		if (ops) {
			ctx.secy = &macsec->secy;
			err = macsec_offload(ops->mdo_add_secy, &ctx);
			if (err)
				goto del_dev;

			macsec->insert_tx_tag =
				macsec_needs_tx_tag(macsec, ops);
		}
	}

	err = register_macsec_dev(real_dev, dev);
	if (err < 0)
		goto del_dev;

	netif_stacked_transfer_operstate(real_dev, dev);
	linkwatch_fire_event(dev);

	macsec_generation++;

	return 0;

del_dev:
	macsec_del_dev(macsec);
unlink:
	netdev_upper_dev_unlink(real_dev, dev);
unregister:
	unregister_netdevice(dev);
	return err;
}

static int macsec_validate_attr(struct nlattr *tb[], struct nlattr *data[],
				struct netlink_ext_ack *extack)
{
	u64 csid = MACSEC_DEFAULT_CIPHER_ID;
	u8 icv_len = MACSEC_DEFAULT_ICV_LEN;
	int flag;
	bool es, scb, sci;

	if (!data)
		return 0;

	if (data[IFLA_MACSEC_CIPHER_SUITE])
		csid = nla_get_u64(data[IFLA_MACSEC_CIPHER_SUITE]);

	if (data[IFLA_MACSEC_ICV_LEN]) {
		icv_len = nla_get_u8(data[IFLA_MACSEC_ICV_LEN]);
		if (icv_len != MACSEC_DEFAULT_ICV_LEN) {
			char dummy_key[DEFAULT_SAK_LEN] = { 0 };
			struct crypto_aead *dummy_tfm;

			dummy_tfm = macsec_alloc_tfm(dummy_key,
						     DEFAULT_SAK_LEN,
						     icv_len);
			if (IS_ERR(dummy_tfm))
				return PTR_ERR(dummy_tfm);
			crypto_free_aead(dummy_tfm);
		}
	}

	switch (csid) {
	case MACSEC_CIPHER_ID_GCM_AES_128:
	case MACSEC_CIPHER_ID_GCM_AES_256:
	case MACSEC_CIPHER_ID_GCM_AES_XPN_128:
	case MACSEC_CIPHER_ID_GCM_AES_XPN_256:
	case MACSEC_DEFAULT_CIPHER_ID:
		if (icv_len < MACSEC_MIN_ICV_LEN ||
		    icv_len > MACSEC_STD_ICV_LEN)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	if (data[IFLA_MACSEC_ENCODING_SA]) {
		if (nla_get_u8(data[IFLA_MACSEC_ENCODING_SA]) >= MACSEC_NUM_AN)
			return -EINVAL;
	}

	for (flag = IFLA_MACSEC_ENCODING_SA + 1;
	     flag < IFLA_MACSEC_VALIDATION;
	     flag++) {
		if (data[flag]) {
			if (nla_get_u8(data[flag]) > 1)
				return -EINVAL;
		}
	}

	es  = data[IFLA_MACSEC_ES] ? nla_get_u8(data[IFLA_MACSEC_ES]) : false;
	sci = data[IFLA_MACSEC_INC_SCI] ? nla_get_u8(data[IFLA_MACSEC_INC_SCI]) : false;
	scb = data[IFLA_MACSEC_SCB] ? nla_get_u8(data[IFLA_MACSEC_SCB]) : false;

	if ((sci && (scb || es)) || (scb && es))
		return -EINVAL;

	if (data[IFLA_MACSEC_VALIDATION] &&
	    nla_get_u8(data[IFLA_MACSEC_VALIDATION]) > MACSEC_VALIDATE_MAX)
		return -EINVAL;

	if ((data[IFLA_MACSEC_REPLAY_PROTECT] &&
	     nla_get_u8(data[IFLA_MACSEC_REPLAY_PROTECT])) &&
	    !data[IFLA_MACSEC_WINDOW])
		return -EINVAL;

	return 0;
}

static struct net *macsec_get_link_net(const struct net_device *dev)
{
	return dev_net(macsec_priv(dev)->real_dev);
}

struct net_device *macsec_get_real_dev(const struct net_device *dev)
{
	return macsec_priv(dev)->real_dev;
}
EXPORT_SYMBOL_GPL(macsec_get_real_dev);

bool macsec_netdev_is_offloaded(struct net_device *dev)
{
	return macsec_is_offloaded(macsec_priv(dev));
}
EXPORT_SYMBOL_GPL(macsec_netdev_is_offloaded);

static size_t macsec_get_size(const struct net_device *dev)
{
	return  nla_total_size_64bit(8) + /* IFLA_MACSEC_SCI */
		nla_total_size(1) + /* IFLA_MACSEC_ICV_LEN */
		nla_total_size_64bit(8) + /* IFLA_MACSEC_CIPHER_SUITE */
		nla_total_size(4) + /* IFLA_MACSEC_WINDOW */
		nla_total_size(1) + /* IFLA_MACSEC_ENCODING_SA */
		nla_total_size(1) + /* IFLA_MACSEC_ENCRYPT */
		nla_total_size(1) + /* IFLA_MACSEC_PROTECT */
		nla_total_size(1) + /* IFLA_MACSEC_INC_SCI */
		nla_total_size(1) + /* IFLA_MACSEC_ES */
		nla_total_size(1) + /* IFLA_MACSEC_SCB */
		nla_total_size(1) + /* IFLA_MACSEC_REPLAY_PROTECT */
		nla_total_size(1) + /* IFLA_MACSEC_VALIDATION */
		nla_total_size(1) + /* IFLA_MACSEC_OFFLOAD */
		0;
}

static int macsec_fill_info(struct sk_buff *skb,
			    const struct net_device *dev)
{
	struct macsec_tx_sc *tx_sc;
	struct macsec_dev *macsec;
	struct macsec_secy *secy;
	u64 csid;

	macsec = macsec_priv(dev);
	secy = &macsec->secy;
	tx_sc = &secy->tx_sc;

	switch (secy->key_len) {
	case MACSEC_GCM_AES_128_SAK_LEN:
		csid = secy->xpn ? MACSEC_CIPHER_ID_GCM_AES_XPN_128 : MACSEC_DEFAULT_CIPHER_ID;
		break;
	case MACSEC_GCM_AES_256_SAK_LEN:
		csid = secy->xpn ? MACSEC_CIPHER_ID_GCM_AES_XPN_256 : MACSEC_CIPHER_ID_GCM_AES_256;
		break;
	default:
		goto nla_put_failure;
	}

	if (nla_put_sci(skb, IFLA_MACSEC_SCI, secy->sci,
			IFLA_MACSEC_PAD) ||
	    nla_put_u8(skb, IFLA_MACSEC_ICV_LEN, secy->icv_len) ||
	    nla_put_u64_64bit(skb, IFLA_MACSEC_CIPHER_SUITE,
			      csid, IFLA_MACSEC_PAD) ||
	    nla_put_u8(skb, IFLA_MACSEC_ENCODING_SA, tx_sc->encoding_sa) ||
	    nla_put_u8(skb, IFLA_MACSEC_ENCRYPT, tx_sc->encrypt) ||
	    nla_put_u8(skb, IFLA_MACSEC_PROTECT, secy->protect_frames) ||
	    nla_put_u8(skb, IFLA_MACSEC_INC_SCI, tx_sc->send_sci) ||
	    nla_put_u8(skb, IFLA_MACSEC_ES, tx_sc->end_station) ||
	    nla_put_u8(skb, IFLA_MACSEC_SCB, tx_sc->scb) ||
	    nla_put_u8(skb, IFLA_MACSEC_REPLAY_PROTECT, secy->replay_protect) ||
	    nla_put_u8(skb, IFLA_MACSEC_VALIDATION, secy->validate_frames) ||
	    nla_put_u8(skb, IFLA_MACSEC_OFFLOAD, macsec->offload) ||
	    0)
		goto nla_put_failure;

	if (secy->replay_protect) {
		if (nla_put_u32(skb, IFLA_MACSEC_WINDOW, secy->replay_window))
			goto nla_put_failure;
	}

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops macsec_link_ops __read_mostly = {
	.kind		= "macsec",
	.priv_size	= sizeof(struct macsec_dev),
	.maxtype	= IFLA_MACSEC_MAX,
	.policy		= macsec_rtnl_policy,
	.setup		= macsec_setup,
	.validate	= macsec_validate_attr,
	.newlink	= macsec_newlink,
	.changelink	= macsec_changelink,
	.dellink	= macsec_dellink,
	.get_size	= macsec_get_size,
	.fill_info	= macsec_fill_info,
	.get_link_net	= macsec_get_link_net,
};

static bool is_macsec_master(struct net_device *dev)
{
	return rcu_access_pointer(dev->rx_handler) == macsec_handle_frame;
}

static int macsec_notify(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct net_device *real_dev = netdev_notifier_info_to_dev(ptr);
	LIST_HEAD(head);

	if (!is_macsec_master(real_dev))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_DOWN:
	case NETDEV_UP:
	case NETDEV_CHANGE: {
		struct macsec_dev *m, *n;
		struct macsec_rxh_data *rxd;

		rxd = macsec_data_rtnl(real_dev);
		list_for_each_entry_safe(m, n, &rxd->secys, secys) {
			struct net_device *dev = m->secy.netdev;

			netif_stacked_transfer_operstate(real_dev, dev);
		}
		break;
	}
	case NETDEV_UNREGISTER: {
		struct macsec_dev *m, *n;
		struct macsec_rxh_data *rxd;

		rxd = macsec_data_rtnl(real_dev);
		list_for_each_entry_safe(m, n, &rxd->secys, secys) {
			macsec_common_dellink(m->secy.netdev, &head);
		}

		netdev_rx_handler_unregister(real_dev);
		kfree(rxd);

		unregister_netdevice_many(&head);
		break;
	}
	case NETDEV_CHANGEMTU: {
		struct macsec_dev *m;
		struct macsec_rxh_data *rxd;

		rxd = macsec_data_rtnl(real_dev);
		list_for_each_entry(m, &rxd->secys, secys) {
			struct net_device *dev = m->secy.netdev;
			unsigned int mtu = real_dev->mtu - (m->secy.icv_len +
							    macsec_extra_len(true));

			if (dev->mtu > mtu)
				dev_set_mtu(dev, mtu);
		}
	}
	}

	return NOTIFY_OK;
}

static struct notifier_block macsec_notifier = {
	.notifier_call = macsec_notify,
};

static int __init macsec_init(void)
{
	int err;

	pr_info("MACsec IEEE 802.1AE\n");
	err = register_netdevice_notifier(&macsec_notifier);
	if (err)
		return err;

	err = rtnl_link_register(&macsec_link_ops);
	if (err)
		goto notifier;

	err = genl_register_family(&macsec_fam);
	if (err)
		goto rtnl;

	return 0;

rtnl:
	rtnl_link_unregister(&macsec_link_ops);
notifier:
	unregister_netdevice_notifier(&macsec_notifier);
	return err;
}

static void __exit macsec_exit(void)
{
	genl_unregister_family(&macsec_fam);
	rtnl_link_unregister(&macsec_link_ops);
	unregister_netdevice_notifier(&macsec_notifier);
	rcu_barrier();
}

module_init(macsec_init);
module_exit(macsec_exit);

MODULE_ALIAS_RTNL_LINK("macsec");
MODULE_ALIAS_GENL_FAMILY("macsec");

MODULE_DESCRIPTION("MACsec IEEE 802.1AE");
MODULE_LICENSE("GPL v2");
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/macsec.c b/drivers/net/macsec.c
index 26034f80d4a4..ee2159282573 100644
--- a/drivers/net/macsec.c
+++ b/drivers/net/macsec.c
@@ -3798,8 +3798,7 @@ static void macsec_free_netdev(struct net_device *dev)
 {
 	struct macsec_dev *macsec = macsec_priv(dev);
 
-	if (macsec->secy.tx_sc.md_dst)
-		metadata_dst_free(macsec->secy.tx_sc.md_dst);
+	dst_release(&macsec->secy.tx_sc.md_dst->dst);
 	free_percpu(macsec->stats);
 	free_percpu(macsec->secy.tx_sc.stats);
 
```



# Target Plan

/* 
Plan:
1. Hook the freeing call using checkPreCall:
   • Use the checkPreCall callback to intercept all function calls.
   • In the callback, extract the caller’s callee identifier (using Call.getCalleeIdentifier() with getNameAsString()).
   • Compare the obtained name with the literal string "metadata_dst_free".

2. Validate the free call context:
   • Once a call to metadata_dst_free() is detected, retrieve the function argument (which should be the shared metadata object).
   • Optionally, verify that the argument’s source text does not indicate that its inner field “dst” is being used (this can be done with the utility function ExprHasName() checking for "->dst" in the expression).
   • (If desired, this extra step ensures that we are not misreporting valid use of dst_release() as the bug pattern.)

3. Report the bug:
   • If metadata_dst_free() is used (and the argument is not appropriately dereferenced to its ‘dst’ subobject), emit a bug report.
   • Use a short and clear message such as "Freeing shared metadata with metadata_dst_free() can lead to use‐after‐free; use dst_release() instead."
   • Employ std::make_unique<BasicBugReport> (or PathSensitiveBugReport) to generate the report.

4. Program state considerations:
   • No additional program state maps (e.g., for pointer aliasing) are required since we are simply checking the call’s callee name.
   • Hence, no customization via REGISTER_MAP_WITH_PROGRAMSTATE or similar mechanisms is necessary for this simple check.

Summary:
• In checkPreCall, hook every call event.
• Identify if the function name equals "metadata_dst_free" by extracting its identifier string.
• Optionally, check that its argument does not contain a dereference of the "dst" field.
• If the check is positive, emit a bug report with a concise message indicating that the shared metadata object is being freed directly, recommending the use of dst_release() instead.
*/


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