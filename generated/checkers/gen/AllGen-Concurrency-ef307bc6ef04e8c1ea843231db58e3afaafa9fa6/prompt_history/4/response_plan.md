Plan

1. Program state
- No custom ProgramState is needed. This checker works as an AST-level, whole-TU correlation checker. It stores per-function facts in the checker instance (ordinary C++ containers), then correlates them at the end of analysis.

2. Data recorded in the checker object (global to the checker, not ProgramState)
- For each function body scanned, we collect facts and append to global containers:
  - UnlockedWriteSites: vector of {FD, AssignLoc, FuncName, AfterUnlockFlag}
    - FD: const FieldDecl* of the pointer field written (e.g., urb->hcpriv).
    - AssignLoc: SourceLocation of the assignment to NULL.
    - AfterUnlockFlag: true if immediately after a spin_unlock call before any next spin_lock.
  - ProtectedUseSites: vector of {FD, CheckLocOpt, UseLoc, FuncName}
    - FD: the same pointer field decl.
    - CheckLocOpt: optional SourceLocation of a NULL-check of this FD under lock (if found).
    - UseLoc: SourceLocation of a “use” of this FD under lock (call arg/deref).
- Internal, per-function, transient tracking while scanning:
  - lockDepth: integer tracking current lock nesting. Any lockDepth > 0 means “under lock”.
  - afterUnlock: boolean that is set true at spin_unlock* and reset to false at any later statement (or next lock).
  - currentLockedContext:
    - CheckedFields: SmallSet<const FieldDecl*, N>
    - UsedFields: SmallSet<const FieldDecl*, N>
  - When lockDepth transitions 0 -> 1, start a new currentLockedContext (clear both sets).
  - When lockDepth transitions 1 -> 0 (at unlock), flush the currentLockedContext to ProtectedUseSites: for each FD in UsedFields, emit a ProtectedUseSite with CheckLocOpt set if FD also appears in CheckedFields.

3. Lock/unlock recognition
- Recognize these function names as lock acquisition:
  - "spin_lock", "spin_lock_bh", "spin_lock_irq", "spin_lock_irqsave"
- Recognize these as lock release:
  - "spin_unlock", "spin_unlock_bh", "spin_unlock_irq", "spin_unlock_irqrestore"
- Implement helpers:
  - bool isSpinLockCall(const CallExpr*): check callee identifier name against the list above.
  - bool isSpinUnlockCall(const CallExpr*): same for unlock names.

4. Field key and “NULL” recognition
- Field key: For member expressions with "->" (MemberExpr with isArrow()), use the member’s FieldDecl* (ME->getMemberDecl()) as the stable key (FD). This robustly unifies “obj->hcpriv” across functions.
- Pointer-only filter: Only consider fields whose type is a pointer (FD->getType()->isPointerType()).
- Recognize NULL RHS: Implement isNullExpr(const Expr*):
  - Return true if expr is a null pointer constant:
    - expr->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull)
    - Or EvaluateExprToInt yields 0
    - Or ExprHasName(expr, "NULL", C) is true.
  - This covers 0, NULL, nullptr.

5. “Checked under lock” recognition (NULL check pattern)
- While lockDepth > 0, analyze If conditions and record the pointer field FD if it is being compared to/against NULL:
  - If the IfStmt condition is:
    - UnaryOperator ‘!’ applied to an expression whose subtree contains a MemberExpr with isArrow() to a pointer FD.
    - BinaryOperator (== or !=) where one side is a MemberExpr (->) to pointer FD and the other side is NULL/0/nullptr (via isNullExpr).
  - Extract the involved MemberExpr; get its FD; record FD into currentLockedContext.CheckedFields with CheckLoc set to the IfStmt condition location (first time seen).

6. “Used under lock” recognition (deref or passed to calls)
- While lockDepth > 0, record “use” of FD if either is observed:
  - Call arg use:
    - For every CallExpr, for each argument:
      - Search for a MemberExpr with isArrow() in the argument’s subtree; if found, take its FD.
      - Record FD in currentLockedContext.UsedFields. If functionKnownToDeref(Call, derefParams) returns true, and this argument index is in derefParams, this is a strong “use”. If not known, still record as a weak “use”.
  - Direct deref use:
    - Detect MemberExpr chain like obj->field->...:
      - If you see a MemberExpr ME2 with isArrow() whose base (ignoring casts) is another MemberExpr ME1 with isArrow(), then ME1’s FD is a used pointer (ME1 is dereferenced to access ME2). Record FD in UsedFields.
    - Or detect a UnaryOperator ‘*’ whose subexpression subtree contains a MemberExpr with isArrow() to FD; record FD in UsedFields.

7. Detect unlocked writes to NULL
- For every BinaryOperator assignment under the function body traversal:
  - If it is BO_Assign and LHS is a MemberExpr with isArrow() and FD is pointer-typed:
    - If RHS isNullExpr(RHS) is true and lockDepth == 0:
      - Append an UnlockedWriteSites entry {FD, AssignLoc = LHS->getExprLoc(), FuncName, AfterUnlockFlag = afterUnlock}.
- Maintain afterUnlock:
  - Set afterUnlock = true when encountering a spin_unlock* call.
  - Reset afterUnlock = false when encountering the next statement that is not another unlock (e.g., any non-unlock statement), or upon any subsequent spin_lock* call.

8. Callback implementation details
- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
  - Only process if D has a body and it is a FunctionDecl.
  - Implement a lightweight RecursiveASTVisitor (or manual recursive walk) to traverse the function body statements in source order.
  - Maintain lockDepth, afterUnlock, and currentLockedContext as described.
  - On entering a lock (isSpinLockCall), increment lockDepth; if lockDepth was 0, clear currentLockedContext.
  - On unlocking (isSpinUnlockCall), decrement lockDepth (not below 0). If lockDepth reaches 0:
    - For each FD in currentLockedContext.UsedFields, add a ProtectedUseSite entry:
      - CheckLocOpt is set if FD is also present in CheckedFields (use the recorded first CheckLoc); otherwise leave it empty (we still keep this as a protected use but with weaker confidence).
      - UseLoc is the CallExpr or MemberExpr location used most recently for this FD; recording the first seen “use” location is sufficient.
    - Clear currentLockedContext.
    - Set afterUnlock = true.
  - On any non-unlock statement, if afterUnlock is true, set afterUnlock = false.

- checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
  - Correlate facts across the TU:
    - For each UnlockedWriteSites entry UW with FD = f:
      - If there exists at least one ProtectedUseSites entry PU with the same FD:
        - Prefer reporting when either:
          - UW.AfterUnlockFlag is true, or
          - PU has a CheckLocOpt present (indicating an under-lock NULL-check-and-use pair).
        - Emit a BasicBugReport:
          - BugType: “Concurrent NULL write without lock to field checked/used under spinlock”
          - Location: UW.AssignLoc
          - Message: “Field is set to NULL without holding spinlock, but is checked/used under spinlock in another path; possible race and NULL dereference.”
        - Optionally, add an extra note location (if supported) pointing to PU.UseLoc (or CheckLocOpt) with a brief note “use under lock here”.
    - Deduplicate: only one report per unique (UW.AssignLoc) or per (FD, AssignLoc).

9. Helper routines to implement
- bool isSpinLockCall(const CallExpr *CE)
- bool isSpinUnlockCall(const CallExpr *CE)
- const FieldDecl* getArrowField(const Expr *E)
  - Return the FieldDecl* if E (ignoring casts) is a MemberExpr with isArrow() and its member is a FieldDecl with pointer type; else nullptr.
- bool isNullExpr(const Expr *E)
  - Use isNullPointerConstant or EvaluateExprToInt (from Utility Functions) or ExprHasName(E, "NULL", C).
- const FieldDecl* findFieldInSubtree(const Expr *E)
  - Walk children to find first MemberExpr with isArrow(); return its FieldDecl*.

10. Reporting policy to keep false positives low
- Only report if both:
  - We saw at least one write of FD to NULL outside any lock, and
  - We saw at least one use of FD under a lock that looks meaningful:
    - Preferably a call to a function known to dereference this argument (functionKnownToDeref), or
    - A dereference chain obj->field->... inside the lock, or
    - A call with the same field argument and a preceding NULL-check of that field under the same locked region.
- This “checked-and-used under lock” evidence significantly reduces noise and matches the target pattern.

11. Where to use provided utilities
- EvaluateExprToInt: in isNullExpr to detect literal 0.
- functionKnownToDeref: to mark strong “use” when passing the field to known-deref functions.
- ExprHasName: as a fallback for identifying NULL token and, if needed, to compare source substrings, though FieldDecl* matching should suffice.
- findSpecificTypeInChildren: can be used to quickly locate MemberExpr nodes within arguments/conditions.

12. Message format
- Short and clear:
  - Title: “Unlocked NULL write races with under-lock use of pointer field”
  - Description: “Field is set to NULL without holding the spinlock, but is checked/used under spinlock in another path; possible race and NULL dereference.”

This plan keeps the implementation simple and robust:
- One AST-body scan per function to collect reads/writes and lock context.
- One cross-function correlation pass at end to emit concise, actionable reports for the exact bug pattern in the target patch.
