Plan

1. Program state
- No custom program state is needed. The pattern can be detected with AST/context inspection around kfree-like calls and loop headers, plus a lightweight lock-acquire scan in the surrounding block.

2. Callbacks
- Use only:
  - checkPreCall: to anchor on kfree-like frees, then analyze the surrounding loop and locking.
  - checkASTCodeBody: optional pre-scan to cache nothing; we can skip it to keep the checker simple.

3. Detection strategy in checkPreCall
- Goal: If a kfree (or kvfree) is executed inside a list traversal loop that references a list_head (field with name ending in “_list”), ensure a protecting spinlock on the same base object (field ending in “_lock”) is acquired in the statements preceding the loop. If not, report.

- Step-by-step implementation in checkPreCall:
  1) Match frees:
     - Intercept calls whose callee name is in {"kfree", "kvfree"}.
     - Let S be the Statement of this call.

  2) Ensure we are inside a loop created by Linux list_for_each* macro:
     - Go up the AST from S with findSpecificTypeInParents<ForStmt>(S, C). If no ForStmt, return (not our case).
     - Let FS be that ForStmt.

  3) Extract evidence that FS iterates a kernel list_head:
     - Search for an UnaryOperator with UO_AddrOf under FS (init/cond/inc preferred, but searching FS subtree is fine):
       - Use findSpecificTypeInChildren<UnaryOperator>(FS).
       - Check it is an address-of (&).
       - From that UnaryOperator, find a MemberExpr child: findSpecificTypeInChildren<MemberExpr>(UnaryOpExpr).
       - If no MemberExpr found, bail (cannot prove a list head).
       - Let ME_list be the MemberExpr. If FieldDecl name does not end with "_list", bail (not a list_head).
     - Obtain the base of the list head:
       - BaseExpr = ME_list->getBase()->IgnoreParenImpCasts().
       - If BaseExpr is a DeclRefExpr, get its name string: BaseName = DRE->getDecl()->getNameAsString(). Keep this as a textual fallback.
     - Also compute the precise memory region for the list head field to identify the owning object:
       - ListHeadRegion = getMemRegionFromExpr(UnaryOpExpr, C). This should be a FieldRegion or a locatable region.
       - If ListHeadRegion is a FieldRegion, extract its super region (the base/object region). Call it ListBaseSuperRegion. We will use this to match the lock’s base.

  4) Find the surrounding block and scan for a spin_lock acquisition before the loop:
     - Let CS be the nearest parent CompoundStmt of FS: findSpecificTypeInParents<CompoundStmt>(FS, C).
     - Iterate statements of CS to find the position of FS.
     - Scan all statements preceding FS (from the start of CS up to but not including FS).
     - For each statement P:
       - Recursively inspect all descendant CallExpr nodes in P (iterate children; you can do a small DFS/BFS for CallExprs).
       - For each CallExpr CE:
         - If its callee is one of:
           {"spin_lock", "spin_lock_irqsave", "spin_lock_bh", "_raw_spin_lock", "_raw_spin_lock_irqsave", "raw_spin_lock", "raw_spin_lock_irqsave"}
           then treat it as a potential lock acquisition.
         - Extract its first argument Arg0 (the lock pointer).
         - Try to bind Arg0 to a region: LockRegion = getMemRegionFromExpr(Arg0, C).
            - If LockRegion is a FieldRegion, and its FieldDecl name ends with "_lock":
              - Compute LockBaseSuperRegion = super region of LockRegion.
              - If both ListBaseSuperRegion and LockBaseSuperRegion are non-null and equal, then we consider the protecting spinlock as held for this loop. Set FoundProtectingLock = true and stop scanning.
            - If precise regions cannot be obtained (e.g., due to macro complexity), use a textual fallback:
              - If BaseName is known, and ExprHasName(Arg0, BaseName) && ExprHasName(Arg0, "_lock"), consider the lock matched. Set FoundProtectingLock = true.

     - Note on RAII guard(spinlock_irqsave): This macro typically expands to a DeclStmt with an initializer that calls raw_spin_lock_irqsave internally. The above recursive CallExpr scan of preceding statements will still see that call; no special handling is required.

  5) Emit a report if no protecting lock is found:
     - If FoundProtectingLock is false:
       - Generate a non-fatal error node with C.generateNonFatalErrorNode().
       - Create a PathSensitiveBugReport with a short message like:
         "Freeing list elements without holding the protecting spinlock"
       - Anchor the report at the kfree call expression.
       - Emit with C.emitReport(...).

4. Additional heuristics and constraints to reduce false positives
- Only warn if all of the following hold:
  - The free happens inside a ForStmt.
  - The same ForStmt subtree contains an address-of a field whose name ends with “_list”.
  - The list head base can be identified either via region or simple base variable name, and no spin_lock-like acquisition on a “_lock” field of the same base object is found in the same block before the loop.
- This avoids warning on arbitrary frees in loops and focuses precisely on Linux list traversal plus free.

5. Utility functions usage summary
- findSpecificTypeInParents<ForStmt>(S, C): to locate the enclosing loop.
- findSpecificTypeInParents<CompoundStmt>(FS, C): to get the surrounding block and enable scanning of preceding statements.
- findSpecificTypeInChildren<UnaryOperator>(FS): to find address-of operators; then findSpecificTypeInChildren<MemberExpr>(UnaryOp) to get the list head field.
- getMemRegionFromExpr(E, C): to map "&base->field" and "&base->lock" expressions to regions and compare their super regions (owners).
- ExprHasName(E, "token"): as a fallback textual check for base name and “_lock” when precise regions are unavailable.

6. Notes
- This checker purposely focuses on kernel list traversal/free patterns and spinlock acquisition, matching the bug in gsm_cleanup_mux:
  - mutex_unlock precedes the loop (not required for detection).
  - Two loops traverse &gsm->tx_ctrl_list and &gsm->tx_data_list and kfree entries.
  - No spin_lock on &gsm->tx_lock before the loops.
- The added guard(spinlock_irqsave) in the fix expands to a raw_spin_lock_irqsave call; scanning preceding statements and their CallExpr descendants will correctly recognize it as a lock acquisition and suppress the warning.
