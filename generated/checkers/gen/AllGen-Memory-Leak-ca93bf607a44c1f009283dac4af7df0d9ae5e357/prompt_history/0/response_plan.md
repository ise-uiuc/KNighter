Plan

1) Program state customizations
- REGISTER_SET_WITH_PROGRAMSTATE(MustFreeTemps, const MemRegion*)
  - Tracks live temporary buffers that must be freed with kfree (e.g., results of nvmem_cell_read/kmalloc-like).
- REGISTER_MAP_WITH_PROGRAMSTATE(AllocSiteMap, const MemRegion*, const Stmt*)
  - Remembers the allocation call statement for each temp (for precise bug locations/notes).
- REGISTER_SET_WITH_PROGRAMSTATE(DevmReallocDstSet, const MemRegion*)
  - Marks pointer variables/fields that were just assigned from devm_krealloc and are subsequently checked against NULL.
- (Optional) REGISTER_SET_WITH_PROGRAMSTATE(FreedSet, const MemRegion*)
  - Not strictly necessary, but can be used to debounce double-removal. You can skip it for simplicity.

2) Helper identification functions
- bool isTempAllocLike(const CallEvent &Call)
  - Return true if callee in {"nvmem_cell_read", "kmalloc", "kcalloc", "krealloc", "kstrdup", "kvmalloc"}.
  - For this bug pattern, handling at least "nvmem_cell_read" is sufficient.
- bool isFreeLike(const CallEvent &Call)
  - Return true if callee is "kfree".
- bool isDevmKrealloc(const CallEvent &Call)
  - Return true if callee is "devm_krealloc".
- const MemRegion* getLHSRegionOfEnclosingAssignmentOrInit(const CallEvent &Call, CheckerContext &C)
  - Walk upwards from Call.getOriginExpr() via findSpecificTypeInParents:
    - If BinaryOperator (assignment), get LHS expr and return getMemRegionFromExpr(LHS, C).
    - Else if in DeclStmt with initializer, get the single VarDecl and return its region (via State->getLValue(VarDecl, LCtx).getAsRegion()).
  - Return nullptr if not found.
- bool parseNullCheck(const Stmt *Cond, CheckerContext &C, const Expr *&TestedExpr, bool &NullOnThen)
  - Recognize:
    - if (!X): TestedExpr = X, NullOnThen = true
    - if (X == NULL or X == 0): TestedExpr = X, NullOnThen = true
    - if (NULL == X or 0 == X): TestedExpr = X, NullOnThen = true
    - if (X != NULL or X != 0): TestedExpr = X, NullOnThen = false
  - Return true if a NULL-check recognized, else false.

3) Callbacks and logic

A) checkPostCall
- Track temporary allocations:
  - If isTempAllocLike(Call):
    - Find the LHS/destination region with getLHSRegionOfEnclosingAssignmentOrInit.
    - If found:
      - State = State->add<MustFreeTemps>(MR)
      - State = State->set<AllocSiteMap>(MR, Call.getOriginExpr())  // for reporting
- Track frees:
  - If isFreeLike(Call):
    - Get pointer argument Expr (arg0), get its region MR via getMemRegionFromExpr.
    - If MR: remove from MustFreeTemps and AllocSiteMap (if present).
- Track devm_krealloc assignment targets:
  - If isDevmKrealloc(Call):
    - Find the destination region MR with getLHSRegionOfEnclosingAssignmentOrInit.
    - If found: State = State->add<DevmReallocDstSet>(MR)

B) checkBind
- Keep DevmReallocDstSet fresh:
  - When a store happens, if the LHS region MR is in DevmReallocDstSet but the RHS is not a devm_krealloc call, erase MR from DevmReallocDstSet.
  - Implementation detail:
    - S is typically a BinaryOperator for assignments. Use findSpecificTypeInChildren<CallExpr>(S) to see if RHS is a call, and if so, check isDevmKrealloc on it. If no such call or not devm_krealloc, erase MR from DevmReallocDstSet.
  - This prevents stale “recent devm_krealloc” markers after other writes.

C) checkPreStmt(const ReturnStmt *RS)
- Detect the specific error path and report:
  - Go upwards to IfStmt with findSpecificTypeInParents<IfStmt>(RS, C).
  - If found:
    - Let IfS = that IfStmt. Determine whether RS is in IfS->getThen() or IfS->getElse() (check subtree membership).
    - Use parseNullCheck(IfS->getCond(), ...) to get TestedExpr and NullOnThen.
    - Determine whether RS is in the null-branch:
      - If RS is under Then and NullOnThen == true, or
      - If RS is under Else and NullOnThen == false,
      - then we are in the “NULL branch”.
    - Compute MR_tested = getMemRegionFromExpr(TestedExpr, C).
    - If MR_tested is null, return.
    - Check if MR_tested is in DevmReallocDstSet. If not, return (not a devm_krealloc failure path).
    - Now check for leaking temps:
      - If MustFreeTemps set is empty, return.
      - For each MR_tmp in MustFreeTemps:
        - Emit a bug (one per MR_tmp) or just the first to reduce noise.
        - Build a PathSensitiveBugReport with a short message:
          - "Memory leak: missing kfree of temporary buffer on devm_krealloc failure"
        - Add notes (if available):
          - Allocation site: AllocSiteMap[MR_tmp] as a note location “temporary buffer allocated here”.
          - devm_krealloc site: the Call.getOriginExpr() you saved for MR_tested, if you kept it; otherwise, the IfStmt condition location is good enough.
        - generateNonFatalErrorNode() and C.emitReport(...).

D) checkPreCall (optional alternative to track frees early)
- Same as in checkPostCall for kfree, but you may implement in PreCall instead. Either is fine; keep only one to avoid duplication.

4) Important details and simplifications
- Scope and aliasing:
  - For this checker keep it simple: do not implement alias tracking. Most kernel patterns keep the temp in a single local variable (e.g., efuse). This avoids complexity and is sufficient for the target bug.
- What counts as a “temporary”:
  - At minimum handle nvmem_cell_read (as in the provided patch) and free with kfree.
  - You may optionally include kmalloc/kcalloc/krealloc/kstrdup/kvmalloc to find similar patterns.
- Avoid false positives:
  - Only warn if:
    - The ReturnStmt is inside a branch that checks a pointer against NULL.
    - The checked pointer was the destination of the most recent devm_krealloc (DevmReallocDstSet contains it).
    - There exists at least one currently-live temporary in MustFreeTemps (i.e., not freed yet).
  - This ties the leak specifically to the devm_krealloc failure path.
- Cleanup of state:
  - On function end, CSA discards state; no special cleanup required.

5) Callback summary
- checkPostCall:
  - Populate MustFreeTemps and AllocSiteMap for nvmem_cell_read/kmalloc-like.
  - Remove from MustFreeTemps on kfree.
  - Mark DevmReallocDstSet for the LHS region on devm_krealloc.
- checkBind:
  - If LHS region is in DevmReallocDstSet and RHS is not devm_krealloc call, erase it from DevmReallocDstSet.
- checkPreStmt(ReturnStmt):
  - If in the NULL-branch of an If that tests a region in DevmReallocDstSet, and MustFreeTemps non-empty, report leak.

6) Utility functions usage
- Use getMemRegionFromExpr to get regions from LHS expressions and condition expressions.
- Use findSpecificTypeInParents to:
  - Get the BinaryOperator/DeclStmt that captures the result of a call in checkPostCall.
  - Get the enclosing IfStmt for ReturnStmt in checkPreStmt.
- Use findSpecificTypeInChildren to:
  - Inspect the RHS of an assignment in checkBind to see if it is a devm_krealloc call.
- Use ExprHasName only if you need a fallback textual check; not necessary with the AST approach above.

7) Report format
- Use std::make_unique<PathSensitiveBugReport>.
- Title: "Memory leak on devm_krealloc failure"
- Message (short): "Missing kfree of temporary buffer when devm_krealloc fails"
- Attach allocation site of the temporary (AllocSiteMap[MR_tmp]) and the If condition location or the devm_krealloc call site as path notes.
