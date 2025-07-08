# Instruction

You are proficient in writing CSA checkers. 

You will be provided with a **bug pattern** description and the corresponding patch to help you undestand this bug pattern. 

I am going to write a CSA checker to detect such **bug pattern**. 
Please organize a elaborate plan to help me write this checker. 

You will also be provided with some **utility functions** to help organize your plan. 
These functions are already implemented and you can include them in your plan. 
These functions will be provided in the `Utility Functions` section. 

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




# Target Patch

## Patch Description

drm/amd/display: Fix possible buffer overflow in 'find_dcfclk_for_voltage()'

when 'find_dcfclk_for_voltage()' function is looping over
VG_NUM_SOC_VOLTAGE_LEVELS (which is 8), but the size of the DcfClocks
array is VG_NUM_DCFCLK_DPM_LEVELS (which is 7).

When the loop variable i reaches 7, the function tries to access
clock_table->DcfClocks[7]. However, since the size of the DcfClocks
array is 7, the valid indices are 0 to 6. Index 7 is beyond the size of
the array, leading to a buffer overflow.

Reported by smatch & thus fixing the below:
drivers/gpu/drm/amd/amdgpu/../display/dc/clk_mgr/dcn301/vg_clk_mgr.c:550 find_dcfclk_for_voltage() error: buffer overflow 'clock_table->DcfClocks' 7 <= 7

Fixes: 3a83e4e64bb1 ("drm/amd/display: Add dcn3.01 support to DC (v2)")
Cc: Roman Li <Roman.Li@amd.com>
Cc: Rodrigo Siqueira <Rodrigo.Siqueira@amd.com>
Cc: Aurabindo Pillai <aurabindo.pillai@amd.com>
Signed-off-by: Srinivasan Shanmugam <srinivasan.shanmugam@amd.com>
Reviewed-by: Roman Li <roman.li@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
static unsigned int find_dcfclk_for_voltage(const struct vg_dpm_clocks *clock_table,
		unsigned int voltage)
{
	int i;

	for (i = 0; i < VG_NUM_SOC_VOLTAGE_LEVELS; i++) {
		if (clock_table->SocVoltage[i] == voltage)
			return clock_table->DcfClocks[i];
	}

	ASSERT(0);
	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c b/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
index a5489fe6875f..aa9fd1dc550a 100644
--- a/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
+++ b/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
@@ -546,6 +546,8 @@ static unsigned int find_dcfclk_for_voltage(const struct vg_dpm_clocks *clock_ta
 	int i;
 
 	for (i = 0; i < VG_NUM_SOC_VOLTAGE_LEVELS; i++) {
+		if (i >= VG_NUM_DCFCLK_DPM_LEVELS)
+			break;
 		if (clock_table->SocVoltage[i] == voltage)
 			return clock_table->DcfClocks[i];
 	}
```



# Target Pattern

## Bug Pattern

The bug pattern is an out-of-bounds access caused by iterating over an index range larger than the actual size of an array. In this case, the loop uses a limit based on VG_NUM_SOC_VOLTAGE_LEVELS (8) while accessing the DcfClocks array which only has VG_NUM_DCFCLK_DPM_LEVELS (7) elements. This mismatch between the loop iteration count and the array's allocated size leads to a possible buffer overflow when the index exceeds the array’s bounds.



# Suggestions 

1. To hook an `if` statement, use the callback function `check::BranchCondition`.

2. If it involves the macro value (like `CMD_XXX`), please use `getNameAsString()` to get the string of the macro value and compare it with the target string.

3. If there are pointer analysis, please use a program state (e.g. `REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)`) and `checkBind` to track the aliasing information.

4. When using `checkBind` for pointer analysis, please use the program state (e.g. `REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)`).

5. The report message should be **short** and clear. Use `std::make_unique<PathSensitiveBugReport>` or `std::make_unique<BasicBugReport>` to create a bug report.

# Formatting

Your plan should contain the following information. 

1. Decide if it's necessary to customize program states (like `REGISTER_TRAIT_WITH_PROGRAMSTATE`, `REGISTER_MAP_WITH_PROGRAMSTATE`). 

2. Choose callback functions. And for every step, detailedly explain how to implement this callback function.

You only need to tell me the way to implement this checker, extra information like unit testing or documentation is unnecessary.

**Please try to use the simplest way and fewer steps to achieve your goal. But for every step, your response should be as concrete as possible so that I can easily follow your guidance and write a correct checker!**

# Plan

Your plan should follow the format of examples plans
Note, your plan should be concise and clear. Do not include unnecessary information or example implementation code snippets.

```
Your plan here
```