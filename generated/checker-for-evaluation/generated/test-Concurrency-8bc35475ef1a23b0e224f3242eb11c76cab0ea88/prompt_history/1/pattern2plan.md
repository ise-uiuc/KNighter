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

workqueue: Fix spruious data race in __flush_work()

When flushing a work item for cancellation, __flush_work() knows that it
exclusively owns the work item through its PENDING bit. 134874e2eee9
("workqueue: Allow cancel_work_sync() and disable_work() from atomic
contexts on BH work items") added a read of @work->data to determine whether
to use busy wait for BH work items that are being canceled. While the read
is safe when @from_cancel, @work->data was read before testing @from_cancel
to simplify code structure:

	data = *work_data_bits(work);
	if (from_cancel &&
	    !WARN_ON_ONCE(data & WORK_STRUCT_PWQ) && (data & WORK_OFFQ_BH)) {

While the read data was never used if !@from_cancel, this could trigger
KCSAN data race detection spuriously:

  ==================================================================
  BUG: KCSAN: data-race in __flush_work / __flush_work

  write to 0xffff8881223aa3e8 of 8 bytes by task 3998 on cpu 0:
   instrument_write include/linux/instrumented.h:41 [inline]
   ___set_bit include/asm-generic/bitops/instrumented-non-atomic.h:28 [inline]
   insert_wq_barrier kernel/workqueue.c:3790 [inline]
   start_flush_work kernel/workqueue.c:4142 [inline]
   __flush_work+0x30b/0x570 kernel/workqueue.c:4178
   flush_work kernel/workqueue.c:4229 [inline]
   ...

  read to 0xffff8881223aa3e8 of 8 bytes by task 50 on cpu 1:
   __flush_work+0x42a/0x570 kernel/workqueue.c:4188
   flush_work kernel/workqueue.c:4229 [inline]
   flush_delayed_work+0x66/0x70 kernel/workqueue.c:4251
   ...

  value changed: 0x0000000000400000 -> 0xffff88810006c00d

Reorganize the code so that @from_cancel is tested before @work->data is
accessed. The only problem is triggering KCSAN detection spuriously. This
shouldn't need READ_ONCE() or other access qualifiers.

No functional changes.

Signed-off-by: Tejun Heo <tj@kernel.org>
Reported-by: syzbot+b3e4f2f51ed645fd5df2@syzkaller.appspotmail.com
Fixes: 134874e2eee9 ("workqueue: Allow cancel_work_sync() and disable_work() from atomic contexts on BH work items")
Link: http://lkml.kernel.org/r/000000000000ae429e061eea2157@google.com
Cc: Jens Axboe <axboe@kernel.dk>

## Buggy Code

```c
// kernel/workqueue.c
static bool __flush_work(struct work_struct *work, bool from_cancel)
{
	struct wq_barrier barr;
	unsigned long data;

	if (WARN_ON(!wq_online))
		return false;

	if (WARN_ON(!work->func))
		return false;

	if (!start_flush_work(work, &barr, from_cancel))
		return false;

	/*
	 * start_flush_work() returned %true. If @from_cancel is set, we know
	 * that @work must have been executing during start_flush_work() and
	 * can't currently be queued. Its data must contain OFFQ bits. If @work
	 * was queued on a BH workqueue, we also know that it was running in the
	 * BH context and thus can be busy-waited.
	 */
	data = *work_data_bits(work);
	if (from_cancel &&
	    !WARN_ON_ONCE(data & WORK_STRUCT_PWQ) && (data & WORK_OFFQ_BH)) {
		/*
		 * On RT, prevent a live lock when %current preempted soft
		 * interrupt processing or prevents ksoftirqd from running by
		 * keeping flipping BH. If the BH work item runs on a different
		 * CPU then this has no effect other than doing the BH
		 * disable/enable dance for nothing. This is copied from
		 * kernel/softirq.c::tasklet_unlock_spin_wait().
		 */
		while (!try_wait_for_completion(&barr.done)) {
			if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
				local_bh_disable();
				local_bh_enable();
			} else {
				cpu_relax();
			}
		}
	} else {
		wait_for_completion(&barr.done);
	}

	destroy_work_on_stack(&barr.work);
	return true;
}
```

## Bug Fix Patch

```diff
diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index d56bd2277e58..ef174d8c1f63 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -4166,7 +4166,6 @@ static bool start_flush_work(struct work_struct *work, struct wq_barrier *barr,
 static bool __flush_work(struct work_struct *work, bool from_cancel)
 {
 	struct wq_barrier barr;
-	unsigned long data;
 
 	if (WARN_ON(!wq_online))
 		return false;
@@ -4184,29 +4183,35 @@ static bool __flush_work(struct work_struct *work, bool from_cancel)
 	 * was queued on a BH workqueue, we also know that it was running in the
 	 * BH context and thus can be busy-waited.
 	 */
-	data = *work_data_bits(work);
-	if (from_cancel &&
-	    !WARN_ON_ONCE(data & WORK_STRUCT_PWQ) && (data & WORK_OFFQ_BH)) {
-		/*
-		 * On RT, prevent a live lock when %current preempted soft
-		 * interrupt processing or prevents ksoftirqd from running by
-		 * keeping flipping BH. If the BH work item runs on a different
-		 * CPU then this has no effect other than doing the BH
-		 * disable/enable dance for nothing. This is copied from
-		 * kernel/softirq.c::tasklet_unlock_spin_wait().
-		 */
-		while (!try_wait_for_completion(&barr.done)) {
-			if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
-				local_bh_disable();
-				local_bh_enable();
-			} else {
-				cpu_relax();
+	if (from_cancel) {
+		unsigned long data = *work_data_bits(work);
+
+		if (!WARN_ON_ONCE(data & WORK_STRUCT_PWQ) &&
+		    (data & WORK_OFFQ_BH)) {
+			/*
+			 * On RT, prevent a live lock when %current preempted
+			 * soft interrupt processing or prevents ksoftirqd from
+			 * running by keeping flipping BH. If the BH work item
+			 * runs on a different CPU then this has no effect other
+			 * than doing the BH disable/enable dance for nothing.
+			 * This is copied from
+			 * kernel/softirq.c::tasklet_unlock_spin_wait().
+			 */
+			while (!try_wait_for_completion(&barr.done)) {
+				if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
+					local_bh_disable();
+					local_bh_enable();
+				} else {
+					cpu_relax();
+				}
 			}
+			goto out_destroy;
 		}
-	} else {
-		wait_for_completion(&barr.done);
 	}
 
+	wait_for_completion(&barr.done);
+
+out_destroy:
 	destroy_work_on_stack(&barr.work);
 	return true;
 }
```



# Target Pattern

## Bug Pattern

Reading a shared field (work->data) unconditionally before verifying that its value is needed (by checking the from_cancel flag) can trigger spurious data race detections. The problematic pattern is accessing unprotected shared state without first confirming the conditions under which that read is required, leading to false-positive race reports by tools like KCSAN.



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