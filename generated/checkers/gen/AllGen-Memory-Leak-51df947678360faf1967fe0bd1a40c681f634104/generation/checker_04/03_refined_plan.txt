Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(LoopAllocSymMap, const Stmt*, SymbolRef)
  - Key: the enclosing loop statement (ForStmt/WhileStmt/DoStmt) that we are currently inside.
  - Value: the SymbolRef of the per-iteration resource allocated in this iteration (e.g., the pointer returned by alloc_etherdev()).
  - Rationale: we only need to remember “the current iteration’s” allocation per loop to decide whether an early bail-out leaks it. Overwrite the value on a new allocation in the same loop to avoid carrying entries from previous iterations.
- (Optional, only if you want slightly better precision) REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, SymbolRef)
  - Track aliases by binding a region (variable/field) to the symbol it stores. Use checkBind to update. This helps match free_netdev(rep->netdev) to the same symbol returned by alloc_etherdev(). If you want to keep things simpler, you can skip this map; the base case with a plain variable (e.g., free_netdev(ndev)) is already handled using symbols directly.

2. Helper identification
- isPerIterAllocator(const CallEvent&):
  - Return true when callee is one of:
    - "alloc_etherdev"
    - "alloc_etherdev_mqs"
    - "alloc_netdev"
    - "alloc_netdev_mqs"
- isPerIterFree(const CallEvent&):
  - Return true when callee is "free_netdev".
- getEnclosingLoopStmt(const Stmt*, CheckerContext&):
  - Using findSpecificTypeInParents<T> over T in order: ForStmt, WhileStmt, DoStmt. Return the first found; otherwise nullptr.
- thenBranchHasGotoExit(const IfStmt*):
  - Find a GotoStmt inside the Then branch using findSpecificTypeInChildren<GotoStmt>.
  - If found, check its target label’s name (GotoStmt->getLabel()->getName()) equals "exit". Return true iff so.
- thenBranchFirstCallExpr(const IfStmt*):
  - Using findSpecificTypeInChildren<CallExpr> on the Then branch. If found, return it; otherwise nullptr.
- getExprSymbol(const Expr*, CheckerContext&):
  - Fetch SVal with C.getState()->getSVal(E, C.getLocationContext()) and return getAsSymbol() if present.
  - If not a symbol and PtrAliasMap is enabled: getMemRegionFromExpr(E, C), look it up in PtrAliasMap to retrieve the bound symbol.

3. checkPostCall
- Goal: record “current iteration allocation” right where allocation happens.
- Steps:
  - If !isPerIterAllocator(Call), return.
  - Get the return symbol: if SymbolRef RetSym = Call.getReturnValue().getAsSymbol(); if null, return.
  - Get the current enclosing loop for the call site (Call.getOriginExpr()) via getEnclosingLoopStmt. If none, return.
  - Overwrite LoopAllocSymMap[LoopStmt] = RetSym. Overwriting ensures we only keep “this iteration’s” most recent per-iteration allocation for that loop.

4. checkPreCall
- Goal: clear the “current iteration allocation” when it is explicitly freed, so the checker will not report on subsequent bail-outs.
- Steps:
  - If !isPerIterFree(Call), return.
  - Obtain the argument symbol SymArg for arg0 using getExprSymbol(Call.getArgExpr(0), C).
  - If no SymArg, return.
  - Iterate LoopAllocSymMap entries. If any entry’s value equals SymArg, remove that map entry for its loop key (this allocation is freed).

5. checkBranchCondition
- Goal: detect “bail-out branches” inside a loop that jump to exit (or return) before reaching the end of the iteration, and verify that the current iteration’s allocation has not been freed.
- Steps:
  - From the Condition, find its IfStmt using findSpecificTypeInParents<IfStmt>.
  - If no IfStmt, return.
  - Find enclosing loop of the IfStmt using getEnclosingLoopStmt(IfStmt, C). If none, return. (We only care about early-exit decisions inside loops.)
  - Extract the Then branch: const Stmt* ThenS = IfS->getThen().
  - Check if ThenS represents a “bail-out”:
    - If thenBranchHasGotoExit(IfS) is true, consider it a bail-out.
    - Else, search for a ReturnStmt in the Then branch using findSpecificTypeInChildren<ReturnStmt>. If found, also consider it a bail-out.
    - If neither goto exit nor return is found in ThenS, return.
  - If it is a bail-out, look up LoopAllocSymMap[LoopStmt]; if not present, return.
  - Precision guard to avoid false positives when the code frees before goto:
    - Let FirstCall = thenBranchFirstCallExpr(IfS). If FirstCall is not null and its callee name is "free_netdev":
      - Get symbol of its first argument ArgSym via getExprSymbol. If ArgSym equals the stored symbol in LoopAllocSymMap[LoopStmt], then do not report (this path frees correctly before bail).
  - If we reach here, report a bug:
    - Message: "Possible leak: per-iteration net_device not freed on error path"
    - Location: Prefer the GotoStmt location if found; otherwise the IfStmt condition.
    - Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.

6. Optional: small enhancements
- Recognize other bail-out idioms:
  - If Then branch contains a BreakStmt that exits the loop and a label-based cleanup resides after the loop, this might or might not be a leak. To keep the checker simple and low-FP, do not handle break/continue; only detect goto exit and return as described.
- Recognize more alloc/free pairs:
  - You can extend isPerIterAllocator/isPerIterFree tables if needed, but keep them narrowly focused to avoid false positives.

7. Why this is sufficient for the target bug pattern
- The target code allocates net_device per iteration and, on an immediate failure (if (err) goto exit;), jumps out without freeing the just-allocated device. Our checker:
  - Records the allocation symbol for the current loop iteration.
  - Sees the early goto exit branch.
  - Verifies that free_netdev was not called on the tracked symbol in that branch.
  - Emits a warning at the bail-out site, prompting the developer to free the current iteration’s resource before the jump.

Notes and usage of provided utilities
- findSpecificTypeInParents and findSpecificTypeInChildren are used to locate the enclosing loop, the IfStmt, and the Goto/Return/Call statements under the Then branch.
- getMemRegionFromExpr and ExprHasName are not required, but you can leverage ExprHasName to match function names in a pinch. Prefer callee identifier accesses for reliability.
- EvaluateExprToInt/inferSymbolMaxVal/getArraySizeFromExpr/getStringSize are not needed here.
