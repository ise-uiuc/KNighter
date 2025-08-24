1) Program state

- Define a set of “currently held spinlocks” so we can know if the code is in a critical section when freeing list nodes.
  - Use REGISTER_MAP_WITH_PROGRAMSTATE(LocksHeld, const MemRegion *, char) as a set (value is unused).
  - A lock key is the MemRegion obtained from the lock expression (the MemberExpr beneath the & operator).

- No other traits/maps are needed.


2) Callback functions and how to implement

A) checkPreCall

Goal: maintain the set of held spinlocks, and detect unprotected frees inside Linux list traversals.

- Identify spinlock acquire:
  - If callee name is one of: "spin_lock", "spin_lock_irqsave", "spin_lock_bh"
  - Extract the first argument Expr (the lock pointer). If it’s a UnaryOperator ‘&’, take its subexpression.
  - Get its MemRegion via getMemRegionFromExpr.
  - If region is non-null, State = State->set<LocksHeld>(Region, 1).
  - Return; do not report.

- Identify spinlock release:
  - If callee name is one of: "spin_unlock", "spin_unlock_irqrestore", "spin_unlock_bh"
  - Extract the first argument (same as above). If ‘&’, take subexpression.
  - Get MemRegion; if non-null, State = State->remove<LocksHeld>(Region).
  - Return; do not report.

- Identify kfree-family call:
  - If callee name in {"kfree", "kvfree", "kmem_cache_free"}:
    - Find the nearest parent ForStmt enclosing this call: use findSpecificTypeInParents<const ForStmt>(S, C), where S is the call’s statement.
    - If not found, return (we only check list-free inside a loop).
    - Verify the enclosing loop is a Linux list traversal:
      - Obtain the loop’s full source text: use Lexer::getSourceText(CharSourceRange::getTokenRange(ForStmt->getSourceRange()), C.getSourceManager(), C.getLangOpts()).
      - Check whether it contains "list_for_each_entry" (including "_safe" variants) via a case-sensitive substring search.
      - If not, return.
    - Optional narrowing to target pattern: If the loop header source also contains "tx_ctrl_list" or "tx_data_list", continue; otherwise you may return to reduce false positives in generic code (you can make this filter configurable, but keep it enabled to match the target bug).
    - Determine if we are protected by a spinlock:
      - First, check if any spinlock is currently held by inspecting whether State->get<LocksHeld>() is non-empty. If non-empty, assume protected and return.
      - If empty, heuristically detect guard(spinlock_irqsave) usage:
        - Find enclosing CompoundStmt of the loop (findSpecificTypeInParents<const CompoundStmt>).
        - Extract its source text and check if it contains "guard(spinlock_irqsave)" before the loop location. If so, assume protected and return.
      - If neither is true, this is unprotected.
    - Report:
      - Create an error node via generateNonFatalErrorNode().
      - Create a PathSensitiveBugReport with a short message: "Freeing list nodes in list_for_each_entry without holding spinlock".
      - Mark the kfree call as the primary location. Optionally add a note at the loop header location: "List traversal here".
      - Emit the report.

Notes:
- We do not attempt to match the exact owning lock (e.g., tx_lock) to the list head; a simpler policy of “some spinlock must be held” keeps the checker simple and effective for the target bug.
- The optional "guard(spinlock_irqsave)" textual heuristic avoids false positives for the fixed pattern in the patch where the lock is taken via the guard macro instead of spin_lock().

B) (No-op) Other callbacks

- checkPostCall, checkBind, checkLocation, checkBranchCondition: not needed for this checker.
- checkASTCodeBody/checkASTDecl: not needed; all detection is done around runtime calls in checkPreCall.


3) Helper routines and heuristics

- isSpinLockAcquire(const CallEvent&):
  - Return true if callee name is one of {"spin_lock", "spin_lock_irqsave", "spin_lock_bh"}.

- isSpinLockRelease(const CallEvent&):
  - Return true if callee name is one of {"spin_unlock", "spin_unlock_irqrestore", "spin_unlock_bh"}.

- isKfreeFamily(const CallEvent&):
  - Return true if callee name is one of {"kfree", "kvfree", "kmem_cache_free"}.

- getLockRegionFromArg(const Expr* Arg, CheckerContext& C):
  - If Arg is UnaryOperator ‘&’, take subexpr; else use Arg directly.
  - Return getMemRegionFromExpr(subexpr, C).

- stmtTextContains(const Stmt* S, StringRef Needle, CheckerContext& C):
  - Use SourceManager/LangOptions and Lexer::getSourceText on S->getSourceRange(), same as ExprHasName but for Stmt.
  - Return substring search result.
  - Use this for detecting "list_for_each_entry" in the loop header and "guard(spinlock_irqsave)" in the enclosing block.

- findEnclosingForStmt(const Stmt* S, CheckerContext& C):
  - return findSpecificTypeInParents<const ForStmt>(S, C).

- findEnclosingCompound(const Stmt* S, CheckerContext& C):
  - return findSpecificTypeInParents<const CompoundStmt>(S, C).


4) Reporting policy

- Only report when:
  - A kfree-family call occurs inside a loop whose header contains "list_for_each_entry".
  - And there is no currently-held spinlock in the state.
  - And there is no textual "guard(spinlock_irqsave)" detected in the enclosing block.
  - Optional filter: loop header contains "tx_ctrl_list" or "tx_data_list" to focus on the target pattern and reduce false positives.
- Message: "Freeing list nodes in list_for_each_entry without holding spinlock".
- Use PathSensitiveBugReport with generateNonFatalErrorNode.
- Avoid duplicate reports by only reporting per kfree call (simple and effective for the target case).


5) Why this catches the target bug

- In the buggy gsm_cleanup_mux(), the list_for_each_entry_safe loops free txq while not holding gsm->tx_lock.
- Our checker:
  - Sees kfree(txq) inside a loop whose header text contains "list_for_each_entry".
  - No prior spin_lock* call active => LocksHeld is empty.
  - No guard(spinlock_irqsave) macro detected (pre-patch).
  - Emits a warning.
- In the fixed code, guard(spinlock_irqsave)(&gsm->tx_lock) appears before the loop; the textual heuristic detects it and suppresses the warning.
