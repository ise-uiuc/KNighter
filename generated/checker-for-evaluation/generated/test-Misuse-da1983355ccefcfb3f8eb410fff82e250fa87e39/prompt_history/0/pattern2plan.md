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

thermal: core: Move initial num_trips assignment before memcpy()

When booting a CONFIG_FORTIFY_SOURCE=y kernel compiled with a toolchain
that supports __counted_by() (such as clang-18 and newer), there is a
panic on boot:

  [    2.913770] memcpy: detected buffer overflow: 72 byte write of buffer size 0
  [    2.920834] WARNING: CPU: 2 PID: 1 at lib/string_helpers.c:1027 __fortify_report+0x5c/0x74
  ...
  [    3.039208] Call trace:
  [    3.041643]  __fortify_report+0x5c/0x74
  [    3.045469]  __fortify_panic+0x18/0x20
  [    3.049209]  thermal_zone_device_register_with_trips+0x4c8/0x4f8

This panic occurs because trips is counted by num_trips but num_trips is
assigned after the call to memcpy(), so the fortify checks think the
buffer size is zero because tz was allocated with kzalloc().

Move the num_trips assignment before the memcpy() to resolve the panic
and ensure that the fortify checks work properly.

Fixes: 9b0a62758665 ("thermal: core: Store zone trips table in struct thermal_zone_device")
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>

## Buggy Code

```c
// drivers/thermal/thermal_core.c
struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					const struct thermal_trip *trips,
					int num_trips, int mask,
					void *devdata,
					const struct thermal_zone_device_ops *ops,
					const struct thermal_zone_params *tzp,
					int passive_delay, int polling_delay)
{
	struct thermal_zone_device *tz;
	int id;
	int result;
	struct thermal_governor *governor;

	if (!type || strlen(type) == 0) {
		pr_err("No thermal zone type defined\n");
		return ERR_PTR(-EINVAL);
	}

	if (strlen(type) >= THERMAL_NAME_LENGTH) {
		pr_err("Thermal zone name (%s) too long, should be under %d chars\n",
		       type, THERMAL_NAME_LENGTH);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * Max trip count can't exceed 31 as the "mask >> num_trips" condition.
	 * For example, shifting by 32 will result in compiler warning:
	 * warning: right shift count >= width of type [-Wshift-count- overflow]
	 *
	 * Also "mask >> num_trips" will always be true with 32 bit shift.
	 * E.g. mask = 0x80000000 for trip id 31 to be RW. Then
	 * mask >> 32 = 0x80000000
	 * This will result in failure for the below condition.
	 *
	 * Check will be true when the bit 31 of the mask is set.
	 * 32 bit shift will cause overflow of 4 byte integer.
	 */
	if (num_trips > (BITS_PER_TYPE(int) - 1) || num_trips < 0 || mask >> num_trips) {
		pr_err("Incorrect number of thermal trips\n");
		return ERR_PTR(-EINVAL);
	}

	if (!ops || !ops->get_temp) {
		pr_err("Thermal zone device ops not defined\n");
		return ERR_PTR(-EINVAL);
	}

	if (num_trips > 0 && !trips)
		return ERR_PTR(-EINVAL);

	if (!thermal_class)
		return ERR_PTR(-ENODEV);

	tz = kzalloc(struct_size(tz, trips, num_trips), GFP_KERNEL);
	if (!tz)
		return ERR_PTR(-ENOMEM);

	if (tzp) {
		tz->tzp = kmemdup(tzp, sizeof(*tzp), GFP_KERNEL);
		if (!tz->tzp) {
			result = -ENOMEM;
			goto free_tz;
		}
	}

	INIT_LIST_HEAD(&tz->thermal_instances);
	INIT_LIST_HEAD(&tz->node);
	ida_init(&tz->ida);
	mutex_init(&tz->lock);
	init_completion(&tz->removal);
	id = ida_alloc(&thermal_tz_ida, GFP_KERNEL);
	if (id < 0) {
		result = id;
		goto free_tzp;
	}

	tz->id = id;
	strscpy(tz->type, type, sizeof(tz->type));

	tz->ops = *ops;
	if (!tz->ops.critical)
		tz->ops.critical = thermal_zone_device_critical;

	tz->device.class = thermal_class;
	tz->devdata = devdata;
	memcpy(tz->trips, trips, num_trips * sizeof(*trips));
	tz->num_trips = num_trips;

	thermal_set_delay_jiffies(&tz->passive_delay_jiffies, passive_delay);
	thermal_set_delay_jiffies(&tz->polling_delay_jiffies, polling_delay);

	/* sys I/F */
	/* Add nodes that are always present via .groups */
	result = thermal_zone_create_device_groups(tz, mask);
	if (result)
		goto remove_id;

	/* A new thermal zone needs to be updated anyway. */
	atomic_set(&tz->need_update, 1);

	result = dev_set_name(&tz->device, "thermal_zone%d", tz->id);
	if (result) {
		thermal_zone_destroy_device_groups(tz);
		goto remove_id;
	}
	result = device_register(&tz->device);
	if (result)
		goto release_device;

	/* Update 'this' zone's governor information */
	mutex_lock(&thermal_governor_lock);

	if (tz->tzp)
		governor = __find_governor(tz->tzp->governor_name);
	else
		governor = def_governor;

	result = thermal_set_governor(tz, governor);
	if (result) {
		mutex_unlock(&thermal_governor_lock);
		goto unregister;
	}

	mutex_unlock(&thermal_governor_lock);

	if (!tz->tzp || !tz->tzp->no_hwmon) {
		result = thermal_add_hwmon_sysfs(tz);
		if (result)
			goto unregister;
	}

	mutex_lock(&thermal_list_lock);
	mutex_lock(&tz->lock);
	list_add_tail(&tz->node, &thermal_tz_list);
	mutex_unlock(&tz->lock);
	mutex_unlock(&thermal_list_lock);

	/* Bind cooling devices for this zone */
	bind_tz(tz);

	thermal_zone_device_init(tz);
	/* Update the new thermal zone and mark it as already updated. */
	if (atomic_cmpxchg(&tz->need_update, 1, 0))
		thermal_zone_device_update(tz, THERMAL_EVENT_UNSPECIFIED);

	thermal_notify_tz_create(tz);

	thermal_debug_tz_add(tz);

	return tz;

unregister:
	device_del(&tz->device);
release_device:
	put_device(&tz->device);
remove_id:
	ida_free(&thermal_tz_ida, id);
free_tzp:
	kfree(tz->tzp);
free_tz:
	kfree(tz);
	return ERR_PTR(result);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/thermal/thermal_core.c b/drivers/thermal/thermal_core.c
index bb21f78b4bfa..1eabc8ebe27d 100644
--- a/drivers/thermal/thermal_core.c
+++ b/drivers/thermal/thermal_core.c
@@ -1354,8 +1354,8 @@ thermal_zone_device_register_with_trips(const char *type,
 
 	tz->device.class = thermal_class;
 	tz->devdata = devdata;
-	memcpy(tz->trips, trips, num_trips * sizeof(*trips));
 	tz->num_trips = num_trips;
+	memcpy(tz->trips, trips, num_trips * sizeof(*trips));
 
 	thermal_set_delay_jiffies(&tz->passive_delay_jiffies, passive_delay);
 	thermal_set_delay_jiffies(&tz->polling_delay_jiffies, polling_delay);
```



# Target Pattern

## Bug Pattern

The bug pattern is an order-of-initialization issue where a structure field used by buffer size checking (via __counted_by for CONFIG_FORTIFY_SOURCE) is updated only after a memcpy() call. In this case, the memory copy operation relies on the num_trips field to determine the bounds of the trips array, but since num_trips is still uninitialized (zero) at the time of memcpy(), the fortify checks detect a buffer overflow. The root of the issue is copying data into a buffer before updating the metadata (buffer size/count) that the security instrumentation uses for bounds verification.



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