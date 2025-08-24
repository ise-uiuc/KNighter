Plan

1. Program state
- Add minimal state to remember “log-and-continue after invalid check” and whether a lock is acquired.
  - REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousNoLockSet, const MemRegion*)
    - Pointers that were invalid-checked but execution did not abort, and no lock was held at that time.
  - REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousAfterLockSet, const MemRegion*)
    - The above pointers moved past a lock acquisition; now any dereference is suspicious.
  - REGISTER_TRAIT_WITH_PROGRAMSTATE(LockDepth, int)
    - Integer nesting counter of lock acquisitions/releases (0 = not locked).

2. Helper predicates and utilities
- isLockAcquire(const CallEvent &Call)
  - True if callee name is one of: spin_lock, spin_lock_irq, spin_lock_irqsave, spin_lock_bh, mutex_lock, rt_mutex_lock, raw_spin_lock (string compare via Call.getCalleeIdentifier()->getName()).
- isLockRelease(const CallEvent &Call)
  - True if callee name is one of: spin_unlock, spin_unlock_irq, spin_unlock_irqrestore, spin_unlock_bh, mutex_unlock, rt_mutex_unlock, raw_spin_unlock.
- extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) -> const MemRegion*
  - Examine Cond recursively for any of:
    - UnaryOperator with opcode UO_LNot and subexpression E that is a pointer-typed DeclRefExpr; return getMemRegionFromExpr(E, C).
    - BinaryOperator (== or !=) with one side an integer constant zero (use EvaluateExprToInt) or null, and the other side a pointer-typed DeclRefExpr; return that DeclRefExpr region.
    - Also handle ParenExpr/ImplicitCastExpr by using IgnoreParenImpCasts().
  - If multiple matches exist, return the first pointer-typed DeclRefExpr region.
- thenHasEarlyExit(const Stmt *Then) -> bool
  - Return true if Then subtree contains ReturnStmt, BreakStmt, ContinueStmt, or GotoStmt (use findSpecificTypeInChildren for each).
- baseRegionOf(SVal Loc) -> const MemRegion*
  - If Loc.getAsRegion() is non-null, climb super-regions until a base region (MemRegion::getBaseRegion()) is found; return it. If no region, return nullptr.

3. checkBranchCondition
- Goal: detect “invalid-check that does not abort” outside the lock.
- Steps:
  - Find the enclosing IfStmt with findSpecificTypeInParents<IfStmt>(Condition, C).
  - Let Cond = IfStmt->getCond(), Then = IfStmt->getThen().
  - R = extractNullCheckedPointer(Cond, C). If null, return.
  - If thenHasEarlyExit(Then) is true, ignore (the code aborts correctly).
  - Read LockDepth from state; if LockDepth > 0, ignore (the validation is already under lock).
  - Add R to SuspiciousNoLockSet in state (State = State->add<SuspiciousNoLockSet>(R)).

4. checkPostCall
- Goal: track lock acquisition/release, and transition suspicious pointers into “after-lock” state.
- On every call:
  - If isLockAcquire(Call):
    - Increment LockDepth (LockDepth = LockDepth + 1).
    - Move all regions in SuspiciousNoLockSet into SuspiciousAfterLockSet:
      - For each R in SuspiciousNoLockSet: add to SuspiciousAfterLockSet.
      - Clear SuspiciousNoLockSet.
    - Update state.
  - Else if isLockRelease(Call):
    - Decrement LockDepth (not going below 0).
    - If LockDepth becomes 0, you may leave SuspiciousAfterLockSet as-is or clear it (optional conservative cleanup). Prefer to keep it until deref is seen or function ends; do not move back to NoLock.

5. checkPreCall
- Goal: catch dereferences via function calls known to dereference pointer arguments.
- Use provided functionKnownToDeref(Call, DerefParams).
  - If it returns true, for each parameter index i in DerefParams:
    - Obtain MemRegion of argument i via getMemRegionFromExpr(Call.getArgExpr(i), C).
    - If the region (or its base region) is in SuspiciousAfterLockSet, report a bug (see 7. Reporting).
    - After reporting, remove the region from SuspiciousAfterLockSet to avoid duplicates.

6. checkLocation
- Goal: catch direct dereferences/field accesses after lock of suspicious pointers.
- For every memory access:
  - Compute Base = baseRegionOf(Loc). If null, return.
  - If Base is in SuspiciousAfterLockSet:
    - Report a bug (see 7. Reporting).
    - Remove Base from SuspiciousAfterLockSet.

7. Reporting
- Create a BugType once (e.g., “Log-and-continue invalid pointer, then deref under lock”).
- When a violation is found (in checkPreCall or checkLocation):
  - Generate a non-fatal error node via generateNonFatalErrorNode().
  - Emit a PathSensitiveBugReport with a short message, e.g.:
    - “Invalid-checked pointer is logged but not aborted; later dereferenced under lock”
  - Optionally add interestingness on the region and involved statements (Condition, lock call, deref site).

8. Cleanup
- checkEndFunction: clear SuspiciousNoLockSet, SuspiciousAfterLockSet, and reset LockDepth to 0.
- checkEndAnalysis: no-op.

9. Notes on precision and robustness
- The checker intentionally does not require the logging call in the then-branch; it only requires that an invalid check (e.g., !ptr or ptr == NULL) happens without an early exit, and that later a lock is acquired before the dereference. This avoids macro-resolution issues for log functions and keeps the signal strong while matching the target pattern.
- The condition parser only extracts DeclRefExpr pointers; this is sufficient for common forms like if (!ir || …). If needed later, extend to handle MemberExpr bases or more complex pointer expressions.
- Aliasing is not tracked to keep the checker simple; the rule focuses on the directly checked pointer name. If aliasing appears commonly, add a PtrAliasMap and update it in checkBind, then check aliases in the Suspicious sets.

Callbacks summary
- checkBranchCondition: detect invalid-check-without-abort outside lock; mark pointer in SuspiciousNoLockSet.
- checkPostCall: track lock/unlock; move SuspiciousNoLockSet -> SuspiciousAfterLockSet on lock; maintain LockDepth.
- checkPreCall: detect deref through known-deref functions on suspicious pointers; report.
- checkLocation: detect direct deref/field access of suspicious pointers; report.
- checkEndFunction: cleanup state.
