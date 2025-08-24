Plan

1) Program state and lightweight global knowledge
- REGISTER_SET_WITH_PROGRAMSTATE(HeldLocks, const MemRegion*)
  - Tracks the set of lock regions currently held on the analyzed path.
- Checker-private global set ProtectedPtrFields
  - A small, per-checker container of strings (canonical source text) for pointer member expressions we observed being NULL-checked while a lock is held (e.g., “urb->hcpriv”). Once a field is in this set, we will treat it as “lock-protected”.
- Checker-private flag per-function (FunctionUsesLocks) to reduce noise
  - Reset in checkBeginFunction; set to true when we see any spin_lock/mutex_lock in this function. We only report if this is true.

2) Helper utilities to implement
- getExprText(const Expr* E, CheckerContext &C) -> std::string
  - Same pattern as ExprHasName utility: use Lexer::getSourceText on E->getSourceRange(). This gives us a canonical string key for MemberExprs and lock expressions.
- getLockArgExpr(const CallEvent &Call) -> const Expr*
  - For spin_lock/spin_lock_irqsave/spin_unlock/spin_unlock_irqrestore/mutex_lock/mutex_unlock, return the “lock” argument expression. For spin_* and mutex_* it is the first argument; for irqsave/irqrestore also first.
  - If the arg is UnaryOperator '&', return its sub-expression to represent the actual lock object (e.g., hsotg->lock).
- isLockAcquire/isLockRelease(const CallEvent &Call)
  - Check callee name matches: spin_lock, spin_lock_bh, spin_lock_irqsave, mutex_lock, mutex_lock_interruptible (acquire);
  - spin_unlock, spin_unlock_bh, spin_unlock_irqrestore, mutex_unlock (release).
- isNullCheckCondition(const Expr* Cond, const MemberExpr* &OutME, CheckerContext &C)
  - Return true if Cond represents any of:
    - UnaryOperator LNot: !X->field
    - BinaryOperator EQ/NE: (X->field == 0/NULL/nullptr) or (X->field != 0/NULL/nullptr)
    - Implicit form: if (X->field) or if (!X->field)
  - If matched, set OutME to the MemberExpr referring to X->field, and ensure OutME->getType()->isPointerType().
  - Use findSpecificTypeInChildren<MemberExpr>(Cond) and simple operator kind checks; for constants use EvaluateExprToInt or text-based fallback (ExprHasName on RHS for "NULL" or "nullptr").
- lhsMemberExprFromStmt(const Stmt *S) -> const MemberExpr*
  - When we get a bind, find the LHS MemberExpr:
    - If S is BinaryOperator with isAssignmentOp, return findSpecificTypeInChildren<MemberExpr>(BO->getLHS()).
    - Else return findSpecificTypeInChildren<MemberExpr>(S) as a best effort.
- rhsIsNull(const Stmt *S, CheckerContext &C) -> bool
  - If S is BinaryOperator, examine RHS:
    - Try EvaluateExprToInt; true if equals 0.
    - Or check ExprHasName(RHS, "NULL", C) or ExprHasName(RHS, "nullptr", C).

3) Callback selection and behavior
- checkBeginFunction(CheckerContext &C)
  - Reset FunctionUsesLocks = false for this function context.

- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - Track lock acquisition:
    - If isLockAcquire(Call):
      - Get lock expression E = getLockArgExpr(Call), then the mem region: const MemRegion* R = getMemRegionFromExpr(E, C).
      - Add R to HeldLocks.
      - FunctionUsesLocks = true.
  - Track lock release:
    - If isLockRelease(Call):
      - Get lock expression E = getLockArgExpr(Call), region R.
      - Remove R from HeldLocks.
  - Optional: while at a call and HeldLocks non-empty, record “use-under-lock” of pointer members passed as arguments. Iterate call arguments; for each MemberExpr ArgME (isArrow() and type is pointer), record its text in ProtectedPtrFields. This is an extra signal, but the main signal is the NULL-check under lock in checkBranchCondition.

- checkBranchCondition(const Stmt *Condition, CheckerContext &C)
  - If HeldLocks is empty, return.
  - Extract the Expr* from Condition (findSpecificTypeInChildren<Expr>).
  - MemberExpr *ME = nullptr; if isNullCheckCondition(CondExpr, ME, C) is true:
    - If ME->getType()->isPointerType():
      - std::string Key = getExprText(ME, C);
      - ProtectedPtrFields.insert(Key).

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
  - Early return if HeldLocks is not empty (we only care about stores outside of any lock).
  - Early return if FunctionUsesLocks == false (avoid noise in functions that never use locks).
  - Find LHS member expression: const MemberExpr *ME = lhsMemberExprFromStmt(S); if !ME return.
  - Ensure ME->isArrow() and ME->getType()->isPointerType().
  - If rhsIsNull(S, C) == false, return (we focus on NULL stores).
  - std::string Key = getExprText(ME, C).
  - If Key not in ProtectedPtrFields, return.
  - At this point, we are assigning NULL to a pointer field that is known to be NULL-checked under a lock elsewhere, and we are not holding any lock now. This matches the target anti-pattern “modify lock-protected shared pointer after unlock.”
  - Report:
    - Generate a non-fatal error node and emit a PathSensitiveBugReport.
    - Message: “Write of lock-protected pointer after unlocking; possible race (TOCTOU).”
    - Optionally, highlight ME’s source range and the whole assignment.

4) Notes and heuristics to reduce false positives
- Only consider pointer-typed MemberExprs for both detection and reporting.
- Only report when:
  - RHS is explicitly NULL/0/nullptr, and
  - No lock is currently held (HeldLocks is empty), and
  - This function uses locking somewhere (FunctionUsesLocks is true), and
  - The field was previously seen NULL-checked under a lock (ProtectedPtrFields contains it).
- Recognize these lock APIs by name string comparisons (spin_lock/spin_unlock/mutex_lock/mutex_unlock including irqsave/irqrestore variants). Extendable.
- For lock expressions that come as &obj->lock:
  - Always extract the operand of unary & as the lock expression before calling getMemRegionFromExpr, so R is stable enough within the function.

5) Why this catches the target bug
- In the buggy function, spin_unlock_irqrestore(&hsotg->lock, flags) is followed by “urb->hcpriv = NULL;”.
- Elsewhere (another function), while the lock is held, there is a NULL check and a subsequent use of urb->hcpriv. During analysis of that other function’s branch condition inside a lock, we record the MemberExpr “urb->hcpriv” as Protected.
- Back in the buggy function, HeldLocks will be empty after the unlock call; the subsequent assignment “urb->hcpriv = NULL;” matches:
  - LHS is a pointer MemberExpr,
  - RHS is NULL,
  - Key “urb->hcpriv” is in ProtectedPtrFields,
  - No lock is held now → report.
- This is exactly the TOCTOU race fixed by moving the assignment before the unlock.

6) Minimal function list and patterns
- Locks to recognize:
  - Acquire: spin_lock, spin_lock_bh, spin_lock_irqsave, mutex_lock, mutex_lock_interruptible.
  - Release: spin_unlock, spin_unlock_bh, spin_unlock_irqrestore, mutex_unlock.
- NULL-check patterns inside a lock:
  - if (!ptr_member)
  - if (ptr_member)
  - if (ptr_member == NULL/0/nullptr)
  - if (ptr_member != NULL/0/nullptr)
- Stores to flag:
  - ptr_member = NULL/0/nullptr outside of any lock, in a function that uses locks.

7) Callbacks summary
- checkBeginFunction: reset FunctionUsesLocks.
- checkPostCall: update HeldLocks on lock/unlock; optionally record “use-under-lock” for call arguments with MemberExprs of pointer type.
- checkBranchCondition: if under a lock, record pointer MemberExprs that are NULL-checked as ProtectedPtrFields.
- checkBind: if not under any lock and assigning NULL to a pointer MemberExpr that is protected, emit report.
