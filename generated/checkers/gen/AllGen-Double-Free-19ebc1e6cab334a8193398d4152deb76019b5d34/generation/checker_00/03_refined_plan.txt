1) Program state
- No custom program state is needed. This checker can be implemented as a single AST-body analysis pass that reasons over labels, gotos, frees, and assignments using source locations.

2) Chosen callbacks
- Use only checkASTCodeBody. We will traverse the function body once, collect a few “events” (labels, gotos, frees, writes), and then run a lightweight dataflow over source-order to spot the pattern.

3) Detailed plan for checkASTCodeBody
A. Collect basic facts from the function body
- Walk the entire body (recursive AST visit) and build these structures:
  - LabelInfos: for each LabelStmt, record:
    - LabelDecl*, Name (LabelStmt->getDecl()->getName()), and SourceLocation (start of label).
  - GotoInfos: for each GotoStmt, record:
    - Target LabelDecl*, and SourceLocation (the goto’s location).
  - FreeEvents: for each CallExpr to a free-like function, record:
    - Callee name in {"kfree", "kvfree", "vfree", "kfree_sensitive"}.
    - The VarDecl* of the freed pointer, if the first argument is a DeclRefExpr (ignore non-DeclRefExpr to reduce FPs).
    - SourceLocation of the call.
  - WriteEvents: for each assignment (BinaryOperator with isAssignmentOp()):
    - If LHS is a DeclRefExpr resolving to VarDecl* V, record V and SourceLocation.
    - Classify the RHS kind:
      - NullInit if RHS is 0, nullptr, GNUNullExpr, or contains "NULL" via ExprHasName(RHS, "NULL", Ctx).
      - AllocWrite if RHS is a CallExpr whose callee is one of {"kmalloc", "kzalloc", "kcalloc", "kvzalloc", "vzalloc", "kmalloc_array", "kcalloc", "kstrdup", "krealloc"}.
      - OtherWrite otherwise.
- Implementation details:
  - Use dyn_cast<BinaryOperator> to find assignments, then inspect LHS and RHS.
  - Use Identifier names for callee detection. For “NULL” macro, use ExprHasName utility.
  - Record only pointer-typed variables (V->getType()->isPointerType()) in FreeEvents and WriteEvents.

B. Identify “cleanup” and “retry” labels from gotos
- For each label L:
  - Cleanup labels: mark L as a cleanup label if it is the target of any forward goto (there exists a GotoStmt G where G.Loc is before L.Loc).
  - Retry labels: mark L as a retry label if it is the target of any backward goto (there exists a GotoStmt G where G.Loc is after L.Loc).
- Keep maps:
  - IsCleanupLabel[LabelDecl*] = true/false.
  - IsRetryLabel[LabelDecl*] = true/false.

C. Associate freed variables to a cleanup label
- For each FreeEvent F(V, LocF):
  - Find a cleanup label C such that:
    - IsCleanupLabel[C] is true, and
    - C.Loc <= LocF, and among such labels choose the nearest (max C.Loc).
  - If none, skip this free (we only want frees that live in a common cleanup tail).
  - To reduce false positives: require that V was allocated at least once before this free:
    - There exists a WriteEvent for V with kind == AllocWrite and WriteLoc < LocF.
  - Create/record a pair (V, CleanupLabel C, FreeLoc LocF). There can be multiple frees; keep each.

D. Confirm the existence of a retry loop after the cleanup
- For each retry label R (IsRetryLabel[R] true):
  - Check that there exists at least one backward goto to R whose GotoLoc is after LocF for some pair in step C (i.e., the code can execute cleanup then jump back to R). If not, the retry loop may not interact with that free; skip that R for that (V,C).

E. Detect the missing NULL reinitialize near the retry label
- For each (V, C, LocF) from step C and each retry label R that passes D:
  - Compute FirstWriteAfterR(V):
    - Among all WriteEvents for V with WriteLoc > R.Loc, take the minimum WriteLoc; if none exists, treat as +infinity.
  - Find any Goto-to-cleanup between R and FirstWriteAfterR(V):
    - Collect all GotoInfos targeting C where R.Loc < GotoLoc < FirstWriteAfterR(V).
    - If none exist, this (R,V) pair is safe; continue.
  - For each such GotoLoc in that range, check if V is re-initialized to NULL before that goto:
    - Look for a NullInit WriteEvent for V with R.Loc < WriteLoc < GotoLoc.
    - If found, this particular path is safe; continue checking other gotos if any.
    - If no NullInit exists before that GotoLoc, report a bug.

F. Reporting
- Create a BasicBugReport with a short message at the retry label or at the first offending goto:
  - Title: “Pointer freed in cleanup is not reset to NULL on retry”
  - Message: “Possible double free: ‘<VName>’ is freed in cleanup and not set to NULL before a goto to cleanup on retry.”
- Point the primary location either at:
  - The retry label R (actionable to set V = NULL near the label), or
  - The first offending goto to C between R and FirstWriteAfterR(V).
- Optionally, add a note at the free site (LocF) to show where the free happens.
- Only one report per (function, V) to avoid duplicates. Track emitted pairs (V, R) in a local set within checkASTCodeBody.

4) Heuristics and helpers
- Free-like functions: {"kfree", "kvfree", "vfree", "kfree_sensitive"}.
- Alloc-like functions: {"kmalloc", "kzalloc", "kcalloc", "kvzalloc", "vzalloc", "kmalloc_array", "kcalloc", "kstrdup", "krealloc"}.
- Null detection:
  - IntegerLiteral zero.
  - CXXNullPtrLiteralExpr, GNUNullExpr.
  - ExprHasName(RHS, "NULL", Ctx) returns true.
- Source ordering:
  - Use SourceManager to compare SourceLocations (ensure both are in the same file; skip cross-file/macro-expansion anomalies if needed by checking isValid() and FileID equality).
- Var extraction:
  - For FreeEvents: arg 0 must be a DeclRefExpr to VarDecl.
  - For WriteEvents: LHS must be a DeclRefExpr to VarDecl.

5) Why this works for the target pattern
- It captures the shape: a backward goto (retry), a forward-goto cleanup with kfree(ptr), and a path from the retry label to cleanup before any write to ptr, without ptr being reset to NULL. That is exactly the cause of double free on retries when an error path jumps to cleanup before re-allocation.
- The heuristic requiring a prior allocation of V before the free reduces false positives where kfree(NULL) is harmless.
