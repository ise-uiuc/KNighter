Plan

1) Program state

- REGISTER_SET_WITH_PROGRAMSTATE(HeldLocks, const MemRegion*)
  - Tracks the set of lock objects currently held (e.g., &hsotg->lock).

- REGISTER_MAP_WITH_PROGRAMSTATE(FieldToLock, const MemRegion*, const MemRegion*)
  - Maps a specific pointer field region (e.g., region of urb->hcpriv) to the lock region under which it has been checked/guarded.

- REGISTER_SET_WITH_PROGRAMSTATE(FieldsUsedUnderLock, const MemRegion*)
  - Tracks fields (same MemRegion* as keys in FieldToLock) that are actually used under the lock (e.g., passed to a function or dereferenced) after being checked.

Rationale:
- We only warn when all three hold: (a) field is known to be protected by a specific lock (FieldToLock), (b) it is actually used under that lock (FieldsUsedUnderLock), and (c) it is later cleared to NULL while that lock is not held (HeldLocks does not contain the protecting lock). This matches the target race with low false positives.


2) Helper recognizers and utilities

- Recognize lock acquire/release calls:
  - Acquire names: "spin_lock", "spin_lock_irqsave", "spin_lock_bh", "mutex_lock", "raw_spin_lock".
  - Release names: "spin_unlock", "spin_unlock_irqrestore", "spin_unlock_bh", "mutex_unlock", "raw_spin_unlock".
  - Extract the lock region from the 1st argument:
    - Strip implicit/paren/addr-of (&) from arg0.
    - Use getMemRegionFromExpr on the underlying lock expression (e.g., hsotg->lock).
    - If a valid MemRegion is found, that is the lock identity to add/remove in HeldLocks.

- Extract a field region from a MemberExpr:
  - For expressions like obj->field (MemberExpr), call getMemRegionFromExpr to get the FieldRegion. This uniquely identifies (Base, FieldDecl) pair and is stable for both reads and writes.

- Detect null constants on assignment:
  - In checkBind, test whether Val is a null pointer constant. Prefer SVal predicates (e.g., Val.isZeroConstant() or checking for a loc::ConcreteInt with zero). If unavailable, fall back to inspecting the RHS expression via S and EvaluateExprToInt to confirm zero.

- Find a pointer field check in a boolean condition:
  - In checkBranchCondition, use findSpecificTypeInChildren<MemberExpr>(Condition) to find a MemberExpr used in the condition. If the MemberExpr type is a pointer type and the condition is a nullness style test (any of: if (ptr), if (!ptr), if (ptr == NULL), if (ptr != NULL)), we treat this as a “check”.
    - You can heuristically accept any pointer-typed MemberExpr appearing in the condition as a check, which keeps the implementation simple.


3) Callback functions and logic

- checkBeginFunction
  - Initialize/clear any per-function bookkeeping if needed (optional; the program state is path-sensitive and starts empty, but explicitly clearing can help).

- checkPostCall
  - Lock acquire:
    - If the callee is one of the Acquire names, extract the lock region and add it to HeldLocks.
  - Lock release:
    - If the callee is one of the Release names, extract the lock region and remove it from HeldLocks.
  - Record “use under lock”:
    - If HeldLocks is non-empty, iterate over call arguments:
      - For each argument, find a MemberExpr with findSpecificTypeInChildren<MemberExpr>(ArgExpr).
      - If found and its type is a pointer, get its FieldRegion via getMemRegionFromExpr.
      - If FieldRegion exists in FieldToLock and the protecting lock for that field is still in HeldLocks, add FieldRegion to FieldsUsedUnderLock.
    - Optionally, also use functionKnownToDeref(Call, DerefParams) to further focus only on calls that are likely to dereference pointer parameters. If DerefParams is non-empty, limit “use under lock” recording to arguments at those indices. If no deref info is available, conservatively record any pointer field argument as a use.

- checkBranchCondition
  - If HeldLocks is empty, do nothing.
  - Otherwise, find a pointer-typed MemberExpr in the condition (as above).
    - Compute FieldRegion for this MemberExpr.
    - Choose a protecting lock from HeldLocks (e.g., the first one in the set).
    - Insert FieldToLock[FieldRegion] = ChosenLockRegion if not already present.
  - This marks that this field is guarded/checked under the lock within this critical section.

- checkBind
  - Triggered on all stores (assignments).
  - Extract LHS region:
    - If Loc.getAsRegion() yields a FieldRegion (e.g., urb->hcpriv), call it FR.
  - Extract assigned value:
    - If Val is a null pointer constant (zero), continue; else return.
  - Decide if this is a “clear outside lock”:
    - If FieldToLock contains FR mapped to LR (protecting lock), and LR is NOT present in HeldLocks at this program point, and FR is present in FieldsUsedUnderLock, then this is the target pattern: clearing a field that is checked-and-used under LR, but the clear happens without LR held.
    - Report a bug.
  - Rationale for the FieldsUsedUnderLock requirement: reduces false positives by ensuring that the field is not just checked but actually used under the lock.

- checkEndFunction
  - Optional: cleanup/reset per-function state (not strictly necessary).


4) Bug report

- When the condition in checkBind is met, create a non-fatal error node and emit a PathSensitiveBugReport with a concise message:
  - “Clearing pointer field outside its lock; may race with locked check/use and cause NULL dereference.”
- Highlight:
  - The assignment statement that writes NULL (primary location).
  - Optionally, add a note at the location where the field was checked/used under lock (using tracked FieldRegion and last known S) to help the user understand the race pattern.


5) Notes and heuristics to keep it simple and effective

- The checker only needs intraprocedural reasoning:
  - If a function checks/uses a field under a lock and later clears it to NULL after unlocking (as in the provided patch), it will be flagged.
- Locks identity:
  - Locks are distinguished by the MemRegion obtained from the first argument of the lock/unlock calls. This robustly handles cases like &hsotg->lock.
- Multiple locks:
  - If multiple locks are held, we bind the field to one specific lock present when it was first checked (the field-to-lock association). Later clears must hold that same lock to be considered safe.
- Conservatism vs precision:
  - Requiring both “checked under lock” and “used under lock” before flagging keeps the warning focused on the check-then-use race pattern instead of all unprotected clears.


6) Minimal use of provided utilities

- findSpecificTypeInChildren<T>(S): to extract MemberExpr from branch conditions and call arguments.
- getMemRegionFromExpr(E, C): to obtain lock MemRegion (from lock API arg) and field MemRegion (from MemberExpr).
- EvaluateExprToInt: only if needed as a fallback to confirm the RHS is zero when detecting null assignments (prefer SVal zero checks).
- functionKnownToDeref: optional precision to only record “use” for calls that likely dereference pointer arguments.


7) Chosen Clang SA callbacks summary

- checkBeginFunction: optional clearing.
- checkPostCall: handle lock acquire/release; record “use under lock” for call arguments.
- checkBranchCondition: record “checked under lock” mapping FieldToLock.
- checkBind: detect “field = NULL” outside the protecting lock and report.
- checkEndFunction: optional clearing.

This plan directly catches the pattern in the target patch: urb->hcpriv is checked and used under spin_lock_irqsave; later, urb->hcpriv = NULL happens after spin_unlock_irqrestore, triggering the warning.
