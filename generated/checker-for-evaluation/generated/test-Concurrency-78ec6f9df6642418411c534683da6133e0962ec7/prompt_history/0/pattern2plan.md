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
// mm/memcontrol.c
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
// mm/memcontrol.c
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



# Target Pattern

## Bug Pattern

Performing non-atomic read-modify-write operations on a shared per-CPU counter. In this patch, the counter (stats_updates) is updated concurrently from different CPU contexts without proper atomic synchronization. The bug arises when a variable used for accumulating statistics is modified using plain arithmetic (e.g., +=) without using atomic primitives or proper memory barriers, allowing concurrent accesses to lead to a data race. The use of READ_ONCE/WRITE_ONCE in the patch ensures that each individual read or write is done atomically, preventing the data race that can occur when multiple CPUs concurrently update a shared statistic.



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