Plan

1. Program State
- REGISTER_TRAIT_WITH_PROGRAMSTATE(TxLockHeld, bool)
  - Tracks whether gsm->tx_lock is currently held on the explored path.
  - Defaults to false.

2. Helper Predicates
- isSpinLockAcquire(const CallEvent &Call)
  - Return true if callee name contains “spin_lock” and does not contain “unlock”.
  - This will match spin_lock, spin_lock_irqsave, spin_lock_bh, raw_spin_lock, etc.
- isSpinUnlock(const CallEvent &Call)
  - Return true if callee name contains “unlock”.
  - This will match spin_unlock, spin_unlock_irqrestore, spin_unlock_bh, raw_spin_unlock, etc.
- callArgHasTxLock(const CallEvent &Call)
  - If Call.getNumArgs() >= 1, return ExprHasName(Call.getArgExpr(0), "tx_lock", C).
  - We only care about locking the tx_lock that protects the lists.
- condUsesTargetLists(const Stmt *Condition, CheckerContext &C)
  - Return true if ExprHasName(cast<Expr>(Condition), "tx_ctrl_list", C) ||
                     ExprHasName(cast<Expr>(Condition), "tx_data_list", C).
  - This detects Linux list_for_each_entry* loop conditions which mention the list head (e.g., &gsm->tx_ctrl_list).
- inTxListLoopForKfree(const CallEvent &Call, CheckerContext &C)
  - Only used for precision when reporting at kfree sites.
  - From Call.getOriginExpr() (the CallExpr), find the nearest parent ForStmt using findSpecificTypeInParents<ForStmt>.
  - If found and its condition exists, return condUsesTargetLists(ForStmt->getCond(), C).
  - Otherwise false.

3. Lock/Unlock Modeling (checkPostCall)
- Purpose: Maintain the TxLockHeld state when the relevant lock is acquired or released.
- Steps:
  - If isSpinLockAcquire(Call) && callArgHasTxLock(Call):
    - State = State->set<TxLockHeld>(true); C.addTransition(State).
  - If isSpinUnlock(Call) && callArgHasTxLock(Call):
    - State = State->set<TxLockHeld>(false); C.addTransition(State).
- Notes:
  - The RAII guard(spinlock_irqsave) macro expands to a spin_lock* call under the hood in the kernel; the lock acquire call will still be visible and matched by isSpinLockAcquire, so no special casing is needed for guard(...).

4. Detect Unlocked Iteration/Destruction (checkBranchCondition)
- Purpose: Flag iteration/destruction of tx_ctrl_list/tx_data_list without holding gsm->tx_lock. This covers list_for_each_entry_safe and similar macros where the loop condition references the list head.
- Steps:
  - If condUsesTargetLists(Condition, C) is true:
    - Read bool Held = State->get<TxLockHeld>() (missing => false).
    - If not Held:
      - Generate a non-fatal error node: ExplodedNode *N = C.generateNonFatalErrorNode();
      - If N is null, return (avoid dup).
      - Create a PathSensitiveBugReport with a short message:
        - “Iterating/freeing tx_* list without holding tx_lock”
      - Attach location to the Condition statement.
      - C.emitReport(std::make_unique<PathSensitiveBugReport>(...)).

5. Precision at Free Sites (optional but simple) (checkPreCall)
- Purpose: Also flag the concrete free of list elements in the list loop if the spinlock isn’t held.
- Steps:
  - If callee name equals “kfree”:
    - If inTxListLoopForKfree(Call, C) is true:
      - Read Held = State->get<TxLockHeld>() (missing => false).
      - If not Held:
        - Generate a non-fatal error node and emit a PathSensitiveBugReport with message:
          - “Freeing tx_* list element without tx_lock”
        - Use the Call source range as the report location.
- This step helps pinpoint the exact freeing site inside the loop.

6. Callbacks Used
- checkPostCall
  - Model spin_lock*/spin_unlock* on tx_lock to update TxLockHeld.
- checkBranchCondition
  - Detect list_for_each_entry* loop conditions that reference tx_ctrl_list/tx_data_list and report if TxLockHeld is false.
- checkPreCall (optional for extra precision at kfree)
  - If freeing within a loop over tx_ctrl_list/tx_data_list and TxLockHeld is false, report.

7. Reporting
- Use a single BugType instance (e.g., “Unlocked list iteration/destruction”) stored in the checker.
- Messages:
  - At loop condition: “Iterating/freeing tx_* list without holding tx_lock”
  - At free site (optional): “Freeing tx_* list element without tx_lock”
- Create reports using std::make_unique<PathSensitiveBugReport>. Keep messages short and clear as suggested.

8. Scope and Heuristics
- This checker intentionally focuses on the concrete target pattern:
  - Only flags when the code references “tx_ctrl_list” or “tx_data_list”.
  - Only requires the specific protecting lock “tx_lock”.
- This keeps the checker simple and reduces false positives.
- It will catch the exact buggy pattern seen in gsm_cleanup_mux before the fix (iterating and freeing tx_* lists without acquiring tx_lock).
