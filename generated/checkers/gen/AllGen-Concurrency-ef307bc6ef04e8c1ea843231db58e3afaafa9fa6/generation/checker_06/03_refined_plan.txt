Plan

1. Program state and per-checker data
- Register a lightweight program state to track the current set of held locks by their declaration identity:
  - REGISTER_SET_WITH_PROGRAMSTATE(HeldLockKeys, const ValueDecl*)
    - Each entry is the ValueDecl of the lock object passed to spin_lock* (either a FieldDecl for struct-member locks like hsotg->lock, or a VarDecl for a global/local lock like foo_lock).
- Maintain a per-checker, cross-function database to associate pointer fields with the locks under which they are used:
  - mutable DenseMap<const FieldDecl*, SmallPtrSet<const ValueDecl*, 2>> FieldProtectingLocks
    - Key: the field being accessed (e.g., urb->hcpriv → the FieldDecl of hcpriv).
    - Value: the set of locks’ ValueDecls observed as being held while this field is checked/used.
  - This is not stored in ProgramState; it persists across functions for the entire TU, allowing us to correlate “writer function” and “reader function”.

2. Recognize lock and unlock calls (checkPreCall)
- Purpose: Maintain the HeldLockKeys set in ProgramState as the analyzer symbolically executes each function, and also detect field “uses under lock” at function-call sites.

- Detect lock acquisition:
  - If callee name equals any of:
    - spin_lock
    - spin_lock_irqsave
    - raw_spin_lock
    - raw_spin_lock_irqsave
  - Extract the first argument (the lock expression). Compute LockKey as:
    - If arg is UnaryOperator(&) over:
      - MemberExpr → use MemberExpr->getMemberDecl() (FieldDecl*) as ValueDecl*.
      - DeclRefExpr → use DeclRefExpr->getDecl() (VarDecl*) as ValueDecl*.
    - If arg is directly DeclRefExpr or MemberExpr (rare), handle similarly.
  - Add LockKey to HeldLockKeys.

- Detect lock release:
  - If callee name equals any of:
    - spin_unlock
    - spin_unlock_irqrestore
    - raw_spin_unlock
    - raw_spin_unlock_irqrestore
  - Extract LockKey from the first argument as above and remove it from HeldLockKeys.

- While visiting any other function call:
  - If HeldLockKeys is non-empty, iterate over the call’s arguments:
    - For each argument, if it is or contains a MemberExpr of a pointer-typed field (MemberExpr->getType()->isPointerType()), get its FieldDecl* F.
      - Record protection: For every lock key currently in HeldLockKeys, insert it into FieldProtectingLocks[F].
      - Note: Getting the MemberExpr: dyn_cast<MemberExpr>(Arg->IgnoreParenImpCasts()) is enough in most cases; if not, use findSpecificTypeInChildren<MemberExpr>(Arg).

3. Detect pointer checks under lock (checkBranchCondition)
- Purpose: Recognize that a pointer field is vetted/checked under a lock, which implies it is intended to be lock-protected.
- If HeldLockKeys is non-empty:
  - Obtain a MemberExpr inside the condition (e.g., if (urb->hcpriv), if (!urb->hcpriv), if (urb->hcpriv == NULL), etc.) using findSpecificTypeInChildren<MemberExpr>(Condition).
  - If found, and the field type is a pointer, get FieldDecl* F and record all currently held lock keys in FieldProtectingLocks[F].

4. Optional: detect general loads under lock (checkLocation)
- Purpose: Robustly capture “field is used under lock” even if not in a call or condition.
- On IsLoad == true and HeldLockKeys is non-empty:
  - From the Stmt S, try findSpecificTypeInChildren<MemberExpr>(S).
  - If a pointer-typed MemberExpr is found, record FieldDecl* F and all current HeldLockKeys in FieldProtectingLocks[F].

5. Detect unsafe writes: clearing a lock-protected pointer outside its protecting lock (checkBind)
- Purpose: Find assignments like urb->hcpriv = NULL that occur while the protecting lock is not held (or a different lock is held).
- When binding a value to a location:
  - Check that Val represents a null/zero:
    - Use SVal API: Val.isZeroConstant().
  - Identify the LHS as a pointer field:
    - From Stmt S (the assignment), locate a MemberExpr using findSpecificTypeInChildren<MemberExpr>(S).
    - Confirm MemberExpr->getType()->isPointerType(), and retrieve FieldDecl* F.
  - Decide if this field is known to be lock-protected elsewhere:
    - Lookup F in FieldProtectingLocks. If not present or empty, do nothing (we didn’t observe it used under lock anywhere, so no mismatch to report).
  - Check currently held locks:
    - Read HeldLockKeys from state. If HeldLockKeys has no intersection with FieldProtectingLocks[F], then we are not holding a protecting lock for this field at this write site.
  - If no protecting lock is currently held, report a bug:
    - Message: “Clearing a lock-protected pointer without holding its lock (possible race).”
    - Optionally, mention the lock’s name using one ValueDecl* from FieldProtectingLocks[F] (e.g., VD->getName()) for clarity.
    - Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.

6. Utility extraction details
- Extracting LockKey from an expression:
  - Strip implicit/paren casts, then:
    - If UnaryOperator with opcode UO_AddrOf:
      - If its subexpr is MemberExpr → FieldDecl*.
      - If its subexpr is DeclRefExpr → VarDecl*.
    - Else if MemberExpr or DeclRefExpr directly, use their decls.
- Extracting FieldDecl from an expression:
  - For a MemberExpr, FieldDecl* is MemberExpr->getMemberDecl().
- Only consider pointer-typed fields for both “use-under-lock” and “clear-to-NULL” events to focus on the target pattern.

7. Chosen callbacks summary
- checkPreCall:
  - Handle spin_lock* and spin_unlock* to maintain HeldLockKeys.
  - For non-lock calls, if HeldLockKeys is non-empty, record any MemberExpr pointer args as protected fields.
- checkBranchCondition:
  - If HeldLockKeys is non-empty, record pointer MemberExprs in conditions as protected fields.
- checkLocation (optional but helpful):
  - If IsLoad and HeldLockKeys is non-empty, record pointer MemberExprs as protected fields.
- checkBind:
  - Detect writes of NULL to MemberExpr pointer fields.
  - If the field is known to be protected elsewhere but no protecting lock is held now, report.

8. Notes and scope
- This checker is intra-TU and cross-function: FieldProtectingLocks is accumulated globally across all analyzed functions, enabling mismatch detection between different functions (e.g., one function reads under hsotg->lock, another clears without any lock).
- Intersection test allows detection even if a different lock is held at the write site (still a mismatch if the protecting lock is not held).
- Focused on Linux-style spin_lock/spin_unlock APIs; more variants can be added similarly if needed.
- The report message should be short and clear as requested.
