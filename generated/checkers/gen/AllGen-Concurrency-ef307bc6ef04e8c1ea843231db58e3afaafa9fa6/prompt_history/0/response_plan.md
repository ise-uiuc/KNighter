Plan

1) Program state

- REGISTER_TRAIT_WITH_PROGRAMSTATE(HeldLocks, LockSet)
  - ImmutableSet<const MemRegion*> representing the currently held locks.
  - We identify a lock by the MemRegion of the first argument passed to spin_lock/spin_unlock (typically the FieldRegion of X->lock or the VarRegion of a lock variable).

- REGISTER_MAP_WITH_PROGRAMSTATE(LockToObjSetMap, const MemRegion*, ImmutableSet<const MemRegion*>)
  - Map from a lock MemRegion L to the set of “object” regions used while holding L.
  - An “object” is the base MemRegion of an expression like obj->field or a pointer variable (e.g., urb) passed as an argument within the critical section protected by L.

- REGISTER_TRAIT_WITH_PROGRAMSTATE(LastUnlockedLock, const MemRegion*)
  - Stores the lock MemRegion of the most recent spin_unlock* call.
  - Cleared as soon as we process the next statement of interest (e.g., any bind or non-unlock call), so “immediately-after-unlock” is enforced and FPs are reduced.

2) Helpers

- isLockAcquire(const CallEvent&): true if callee is one of:
  - "spin_lock", "spin_lock_irqsave", "spin_lock_bh", "spin_lock_irq"
- isLockRelease(const CallEvent&): true if callee is one of:
  - "spin_unlock", "spin_unlock_irqrestore", "spin_unlock_bh", "spin_unlock_irq"
- getLockRegionFromCall(const CallEvent&, CheckerContext&): MemRegion*
  - Returns the region for the first argument of the lock function using getMemRegionFromExpr(Call.getArgExpr(0), C). This becomes the key in HeldLocks/LockToObjSetMap.
- recordObjUseUnderHeldLocks(const Expr *ArgE, CheckerContext &C):
  - If HeldLocks is non-empty, attempt to obtain a base “object” MemRegion:
    - If ArgE is MemberExpr or DeclRefExpr (possibly with casts), get region with getMemRegionFromExpr(ArgE, C).
    - If ArgE is a MemberExpr of the form Base->Field, use Base’s region as the “object” region.
  - For every held lock L in HeldLocks, add the object region into LockToObjSetMap[L].
- isPointerFieldAssignmentToNull(const Stmt *S, SVal Loc, SVal Val, CheckerContext &C):
  - Ensure S is a BinaryOperator assignment with LHS a MemberExpr using “->”.
  - Confirm LHS type is a pointer type.
  - Confirm RHS is NULL/0:
    - Prefer checking Val as an SVal (null location or zero integer), or
    - Use EvaluateExprToInt on RHS and check zero.
- getBaseObjectRegionFromLHS(const BinaryOperator *BO, CheckerContext &C):
  - BO->getLHS() must be a MemberExpr ME; return getMemRegionFromExpr(ME->getBase(), C).

3) Callbacks and logic

A) checkPreCall
- Detect lock acquires:
  - If isLockAcquire(Call), get L = getLockRegionFromCall(Call, C) and add L to HeldLocks.
  - Clear LastUnlockedLock if set (we only want the assignment immediately after unlock).
- While any lock is held, record object uses through arguments:
  - For each argument ArgE of any call (not just locks) when HeldLocks is non-empty, call recordObjUseUnderHeldLocks(ArgE, C).
  - This will capture cases like usb_hcd_link_urb_to_ep(hcd, urb) under lock; it will register urb’s MemRegion as being used under the currently held locks.

B) checkPostCall
- Detect lock releases:
  - If isLockRelease(Call), get L = getLockRegionFromCall(Call, C).
  - Remove L from HeldLocks (if present).
  - Set LastUnlockedLock to L (this marks the unlock that the next statement belongs to).
- Otherwise, if LastUnlockedLock is set and this is a non-unlock call, clear LastUnlockedLock to keep the “immediately-after-unlock” window small.

C) checkLocation
- When HeldLocks is non-empty, we also record object usage on memory accesses:
  - Try to get a MemberExpr ancestor from S via findSpecificTypeInParents<MemberExpr>(S, C).
  - If found and it has a base expression BaseE, record BaseE’s region into LockToObjSetMap for every lock currently in HeldLocks.
  - This complements checkPreCall (so we catch both passing urb under lock as an argument and accessing urb->field under lock).

D) checkBind
- Detect the core pattern:
  - If LastUnlockedLock is set (L_unlocked != nullptr) and HeldLocks is empty:
    - Verify this bind is a pointer field assignment to NULL using isPointerFieldAssignmentToNull(S, Loc, Val, C).
    - If yes:
      - Obtain the base object region ObjR = getBaseObjectRegionFromLHS(BO, C).
      - Fetch the set S_objs = LockToObjSetMap[L_unlocked]. If ObjR is in S_objs:
        - Report bug: setting a shared pointer field of an object (previously used under lock L_unlocked) immediately after releasing that lock.
  - Regardless of detection, clear LastUnlockedLock here (we only allow the immediate next assignment to be considered).
- Note: If the assignment occurs while any lock is still held (HeldLocks non-empty), do nothing (this is the fixed/correct behavior).

E) checkBeginFunction / checkEndFunction
- Optionally clear all state at function entry; not strictly necessary as ProgramState is path-sensitive, but you may reset LastUnlockedLock to nullptr in checkBeginFunction for clarity.

4) Bug report

- When condition in checkBind triggers:
  - Node: generateNonFatalErrorNode(State).
  - Message: “Pointer field set to NULL after unlocking; may race with readers under the lock”
  - Use PathSensitiveBugReport and attach ranges on the assignment LHS.
  - Optionally add notes:
    - At the unlock call site (store source range from the unlock Call and add as a note).
    - At any recorded object use under the lock (if you stored one representative program point), but this is optional; keep it simple.

5) Filters to reduce false positives

- Only trigger when:
  - The LHS is a pointer-typed field (MemberExpr with isArrow(), pointer type).
  - RHS is definitely NULL/0.
  - LastUnlockedLock is set and there are no held locks.
  - The same base object region was used under that lock earlier on this path (exists in LockToObjSetMap[LastUnlockedLock]).
- Clear LastUnlockedLock on any non-unlock call and after any bind event to ensure we focus on the immediate-after-unlock assignment pattern.

6) Utility functions usage

- getMemRegionFromExpr: used to obtain regions for lock arguments and base object expressions.
- findSpecificTypeInParents: used in checkLocation to recover MemberExpr when we see memory accesses.
- EvaluateExprToInt: used in isPointerFieldAssignmentToNull to confirm RHS is zero when needed.
- ExprHasName: optional to check specific lock names if needed, but prefer CallEvent.getCalleeIdentifier().

7) Summary of callback roles

- checkPreCall: track lock acquisitions, record object usage under held locks, clear LastUnlockedLock on other calls.
- checkPostCall: track lock releases and set LastUnlockedLock.
- checkLocation: record object usage under held locks when accessing members.
- checkBind: detect “unlock then set obj->ptr = NULL” for an object previously used under that lock and report.
- checkBeginFunction: initialize LastUnlockedLock to null (optional).
