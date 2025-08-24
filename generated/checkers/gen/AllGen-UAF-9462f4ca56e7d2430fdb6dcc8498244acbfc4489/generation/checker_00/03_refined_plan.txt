Plan: Detect freeing tx_* list nodes without holding the protecting spinlock (tx_lock)

1. Program State Customization
- REGISTER_SET_WITH_PROGRAMSTATE(HeldTxLocks, const MemRegion*)
  - Tracks currently-held spinlock regions that correspond to tx_lock. We store the MemRegion of &X->tx_lock for any X that is locked.
- Optional: A per-function cache (checker member, not ProgramState) to record functions that contain a target list traversal:
  - llvm::DenseSet<const FunctionDecl*> FnHasTxListLoop
  - This is populated in checkASTCodeBody, so we can cheaply gate kfree checks only in functions that traverse tx_ctrl_list/tx_data_list using list_for_each_entry*.

2. Helper/Utility Usage
- getMemRegionFromExpr: to obtain the MemRegion for the spinlock expressions passed to spin_lock/spin_unlock/guard calls.
- ExprHasName: to match target names directly from source text:
  - Match lock/list names: "tx_lock", "tx_ctrl_list", "tx_data_list".
  - Match macro use: "list_for_each_entry_safe" or "list_for_each_entry".
- findSpecificTypeInParents / findSpecificTypeInChildren:
  - To locate the nearest enclosing loop (ForStmt/WhileStmt) around a kfree call.
- Additional text extraction for Stmt (pattern):
  - Similar to ExprHasName, get source text via Lexer::getSourceText on a Stmt’s CharSourceRange to check if it contains a given substring (use the same approach as in ExprHasName; implement a tiny local helper if needed).

3. Callback Selection and Detailed Steps

A) checkASTCodeBody (per function pre-scan to gate the checker)
- Goal: Identify functions that iterate the target lists using list_for_each_entry*.
- Implementation:
  - Iterate all Stmts in the function body (simple recursive walk).
  - For each loop Stmt (ForStmt/WhileStmt/DoStmt):
    - Extract the source text of the loop header (and/or entire loop Stmt).
    - If the text contains both "list_for_each_entry" (or "list_for_each_entry_safe") and either "tx_ctrl_list" or "tx_data_list", insert the current FunctionDecl into FnHasTxListLoop.
- Rationale: This gate minimizes false positives and avoids expensive analysis in non-relevant functions.

B) checkPreCall (lock/unlock tracking; detect violations at free sites)
- Track acquisition of tx_lock:
  - If callee is spin_lock, spin_lock_irqsave, spin_lock_irq, raw_spin_lock (and variants):
    - Let E be the first argument. If ExprHasName(E, "tx_lock"), insert getMemRegionFromExpr(E) into HeldTxLocks.
  - Handle guard(spinlock_irqsave)(&lock):
    - If callee identifier is "guard" and the call expression’s source contains "spinlock_irqsave", and the first argument’s text contains "tx_lock", then:
      - Insert getMemRegionFromExpr(first-arg) into HeldTxLocks.
      - Note: Do not remove later (RAII releases at scope end). Over-approximation is acceptable for this checker (prevents false positives when guard is used).
- Track release of tx_lock:
  - If callee is spin_unlock, spin_unlock_irqrestore, raw_spin_unlock (and variants):
    - If ExprHasName(first-arg, "tx_lock"), remove getMemRegionFromExpr(first-arg) from HeldTxLocks.
- Detect unsafe free:
  - If callee is kfree (or kvfree):
    - If the current function is not in FnHasTxListLoop, return (not our pattern).
    - Attempt to refine context: find the nearest enclosing loop using findSpecificTypeInParents<ForStmt> and/or <WhileStmt>. If found:
      - Get loop header/source and check if it contains "list_for_each_entry" (or "list_for_each_entry_safe") and either "tx_ctrl_list" or "tx_data_list".
      - If not matched, return (we only care about frees inside such traversals).
    - Check lock held:
      - If HeldTxLocks is empty, report a bug: we are freeing nodes of tx_* list without holding the protecting spinlock.
      - Optionally, if HeldTxLocks is non-empty but none of the regions’ source texts contain "tx_lock", still report (strictly require tx_lock). If you only stored tx_lock regions in HeldTxLocks as stated above, just check empty/non-empty.

C) Optional: checkBeginFunction / checkEndFunction
- Not strictly necessary. HeldTxLocks will naturally reset as analysis leaves the function context.
- No additional state is needed here.

4. Bug Reporting
- When violation is detected in checkPreCall at kfree:
  - Create a non-fatal error node via generateNonFatalErrorNode.
  - Emit a concise PathSensitiveBugReport:
    - Checker name: “KernelListLockingChecker” (or similar).
    - Short message: “Freeing tx_* list entries without holding tx_lock (possible UAF).”
  - Location: the kfree call expression.

5. Notes and Heuristics
- This checker is intentionally focused:
  - Only flags when:
    - The function contains a loop that sources textual tokens “list_for_each_entry” or “list_for_each_entry_safe”, and “tx_ctrl_list” or “tx_data_list”.
    - The kfree call is nested inside such a loop (checked via ancestor loop Stmt’s source).
    - No tx_lock is believed to be held (HeldTxLocks empty).
- Lock detection is name-based (ExprHasName “tx_lock”). This leverages the Linux naming convention in the targeted code and avoids complex aliasing of lock objects.
- RAII guard(spinlock_irqsave) is recognized by callee name "guard" and text token “spinlock_irqsave” in the call expression. We conservatively treat it as acquiring tx_lock for the remainder of the function path (safe for our purposes).

6. Minimal Function List
- Locks:
  - Acquire: spin_lock, spin_lock_irqsave, spin_lock_irq, raw_spin_lock (and variants)
  - Release: spin_unlock, spin_unlock_irqrestore, raw_spin_unlock (and variants)
  - RAII: guard(spinlock_irqsave)( &X->tx_lock )
- Free:
  - kfree (and optionally kvfree)
- Traversal recognition (textual, not calls):
  - list_for_each_entry
  - list_for_each_entry_safe
- Target lists (textual):
  - tx_ctrl_list
  - tx_data_list

7. Summary of Flow
- Pre-scan each function (checkASTCodeBody) to see if it contains a traversal over tx_ctrl_list/tx_data_list.
- Track holding of tx_lock via checkPreCall on lock/unlock and guard constructs.
- On each kfree (checkPreCall), if inside a traversal loop of tx_* list and tx_lock is not held, emit the bug report.
