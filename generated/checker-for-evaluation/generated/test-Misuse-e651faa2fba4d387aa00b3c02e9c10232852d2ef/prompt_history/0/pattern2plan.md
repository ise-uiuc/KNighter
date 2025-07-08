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

drivers/tty/vt: use standard array-copy-functions

tty/vt currently uses memdup_user() and vmemdup_array_user() to copy
userspace arrays.

Whereas there is no danger of overflowing, the call to vmemdup_user()
currently utilizes array_size() to calculate the array size
nevertheless. This is not useful because array_size() would return
SIZE_MAX and pass it to vmemdup_user() in case of (the impossible)
overflow.

string.h from the core-API now provides the wrappers memdup_array_user()
and vmemdup_array_user() to copy userspace arrays in a standardized
manner. Additionally, they also perform generic overflow-checks.

Use these wrappers to make it more obvious and readable that arrays are
being copied.

As we are at it, remove two unnecessary empty lines.

Suggested-by: Dave Airlie <airlied@redhat.com>
Signed-off-by: Philipp Stanner <pstanner@redhat.com>
Link: https://lore.kernel.org/r/20231103111207.74621-2-pstanner@redhat.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Buggy Code

```c
// drivers/tty/vt/keyboard.c
int vt_do_diacrit(unsigned int cmd, void __user *udp, int perm)
{
	unsigned long flags;
	int asize;
	int ret = 0;

	switch (cmd) {
	case KDGKBDIACR:
	{
		struct kbdiacrs __user *a = udp;
		struct kbdiacr *dia;
		int i;

		dia = kmalloc_array(MAX_DIACR, sizeof(struct kbdiacr),
								GFP_KERNEL);
		if (!dia)
			return -ENOMEM;

		/* Lock the diacriticals table, make a copy and then
		   copy it after we unlock */
		spin_lock_irqsave(&kbd_event_lock, flags);

		asize = accent_table_size;
		for (i = 0; i < asize; i++) {
			dia[i].diacr = conv_uni_to_8bit(
						accent_table[i].diacr);
			dia[i].base = conv_uni_to_8bit(
						accent_table[i].base);
			dia[i].result = conv_uni_to_8bit(
						accent_table[i].result);
		}
		spin_unlock_irqrestore(&kbd_event_lock, flags);

		if (put_user(asize, &a->kb_cnt))
			ret = -EFAULT;
		else  if (copy_to_user(a->kbdiacr, dia,
				asize * sizeof(struct kbdiacr)))
			ret = -EFAULT;
		kfree(dia);
		return ret;
	}
	case KDGKBDIACRUC:
	{
		struct kbdiacrsuc __user *a = udp;
		void *buf;

		buf = kmalloc_array(MAX_DIACR, sizeof(struct kbdiacruc),
								GFP_KERNEL);
		if (buf == NULL)
			return -ENOMEM;

		/* Lock the diacriticals table, make a copy and then
		   copy it after we unlock */
		spin_lock_irqsave(&kbd_event_lock, flags);

		asize = accent_table_size;
		memcpy(buf, accent_table, asize * sizeof(struct kbdiacruc));

		spin_unlock_irqrestore(&kbd_event_lock, flags);

		if (put_user(asize, &a->kb_cnt))
			ret = -EFAULT;
		else if (copy_to_user(a->kbdiacruc, buf,
				asize*sizeof(struct kbdiacruc)))
			ret = -EFAULT;
		kfree(buf);
		return ret;
	}

	case KDSKBDIACR:
	{
		struct kbdiacrs __user *a = udp;
		struct kbdiacr *dia = NULL;
		unsigned int ct;
		int i;

		if (!perm)
			return -EPERM;
		if (get_user(ct, &a->kb_cnt))
			return -EFAULT;
		if (ct >= MAX_DIACR)
			return -EINVAL;

		if (ct) {

			dia = memdup_user(a->kbdiacr,
					sizeof(struct kbdiacr) * ct);
			if (IS_ERR(dia))
				return PTR_ERR(dia);

		}

		spin_lock_irqsave(&kbd_event_lock, flags);
		accent_table_size = ct;
		for (i = 0; i < ct; i++) {
			accent_table[i].diacr =
					conv_8bit_to_uni(dia[i].diacr);
			accent_table[i].base =
					conv_8bit_to_uni(dia[i].base);
			accent_table[i].result =
					conv_8bit_to_uni(dia[i].result);
		}
		spin_unlock_irqrestore(&kbd_event_lock, flags);
		kfree(dia);
		return 0;
	}

	case KDSKBDIACRUC:
	{
		struct kbdiacrsuc __user *a = udp;
		unsigned int ct;
		void *buf = NULL;

		if (!perm)
			return -EPERM;

		if (get_user(ct, &a->kb_cnt))
			return -EFAULT;

		if (ct >= MAX_DIACR)
			return -EINVAL;

		if (ct) {
			buf = memdup_user(a->kbdiacruc,
					  ct * sizeof(struct kbdiacruc));
			if (IS_ERR(buf))
				return PTR_ERR(buf);
		} 
		spin_lock_irqsave(&kbd_event_lock, flags);
		if (ct)
			memcpy(accent_table, buf,
					ct * sizeof(struct kbdiacruc));
		accent_table_size = ct;
		spin_unlock_irqrestore(&kbd_event_lock, flags);
		kfree(buf);
		return 0;
	}
	}
	return ret;
}
```
```c
// drivers/tty/vt/consolemap.c
int con_set_unimap(struct vc_data *vc, ushort ct, struct unipair __user *list)
{
	int err = 0, err1;
	struct uni_pagedict *dict;
	struct unipair *unilist, *plist;

	if (!ct)
		return 0;

	unilist = vmemdup_user(list, array_size(sizeof(*unilist), ct));
	if (IS_ERR(unilist))
		return PTR_ERR(unilist);

	console_lock();

	/* Save original vc_unipagdir_loc in case we allocate a new one */
	dict = *vc->uni_pagedict_loc;
	if (!dict) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (dict->refcount > 1) {
		dict = con_unshare_unimap(vc, dict);
		if (IS_ERR(dict)) {
			err = PTR_ERR(dict);
			goto out_unlock;
		}
	} else if (dict == dflt) {
		dflt = NULL;
	}

	/*
	 * Insert user specified unicode pairs into new table.
	 */
	for (plist = unilist; ct; ct--, plist++) {
		err1 = con_insert_unipair(dict, plist->unicode, plist->fontpos);
		if (err1)
			err = err1;
	}

	/*
	 * Merge with fontmaps of any other virtual consoles.
	 */
	if (con_unify_unimap(vc, dict))
		goto out_unlock;

	for (enum translation_map m = FIRST_MAP; m <= LAST_MAP; m++)
		set_inverse_transl(vc, dict, m);
	set_inverse_trans_unicode(dict);

out_unlock:
	console_unlock();
	kvfree(unilist);
	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/tty/vt/consolemap.c b/drivers/tty/vt/consolemap.c
index 5e39a4f430ee..82d70083fead 100644
--- a/drivers/tty/vt/consolemap.c
+++ b/drivers/tty/vt/consolemap.c
@@ -644,7 +644,7 @@ int con_set_unimap(struct vc_data *vc, ushort ct, struct unipair __user *list)
 	if (!ct)
 		return 0;
 
-	unilist = vmemdup_user(list, array_size(sizeof(*unilist), ct));
+	unilist = vmemdup_array_user(list, ct, sizeof(*unilist));
 	if (IS_ERR(unilist))
 		return PTR_ERR(unilist);
 
diff --git a/drivers/tty/vt/keyboard.c b/drivers/tty/vt/keyboard.c
index 12a192e1196b..a2116e135a82 100644
--- a/drivers/tty/vt/keyboard.c
+++ b/drivers/tty/vt/keyboard.c
@@ -1772,12 +1772,10 @@ int vt_do_diacrit(unsigned int cmd, void __user *udp, int perm)
 			return -EINVAL;
 
 		if (ct) {
-
-			dia = memdup_user(a->kbdiacr,
-					sizeof(struct kbdiacr) * ct);
+			dia = memdup_array_user(a->kbdiacr,
+						ct, sizeof(struct kbdiacr));
 			if (IS_ERR(dia))
 				return PTR_ERR(dia);
-
 		}
 
 		spin_lock_irqsave(&kbd_event_lock, flags);
@@ -1811,8 +1809,8 @@ int vt_do_diacrit(unsigned int cmd, void __user *udp, int perm)
 			return -EINVAL;
 
 		if (ct) {
-			buf = memdup_user(a->kbdiacruc,
-					  ct * sizeof(struct kbdiacruc));
+			buf = memdup_array_user(a->kbdiacruc,
+						ct, sizeof(struct kbdiacruc));
 			if (IS_ERR(buf))
 				return PTR_ERR(buf);
 		} 
```



# Target Pattern

## Bug Pattern

The bug pattern is relying on legacy user-space array copy functions (memdup_user() and vmemdup_user()) that calculate the copy size using array_size(), which may return an invalid size (like SIZE_MAX in overflow scenarios) despite assumptions that overflow is impossible. This approach lacks explicit generic overflow checks and clear intent, leading to potential miscalculations and obscure code behavior. The fix replaces these calls with the standardized wrappers (memdup_array_user() and vmemdup_array_user()), which not only provide the same functionality but also incorporate proper overflow validations.



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