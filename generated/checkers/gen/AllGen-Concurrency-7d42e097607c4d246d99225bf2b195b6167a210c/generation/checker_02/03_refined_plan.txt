Plan

1. Program state
- No custom program state is required. We will detect this purely from the AST (per-function body scanning) and correlate information across functions at end-of-analysis.

2. Chosen callbacks
- checkASTCodeBody: Scan each function body for two roles:
  - Worker role: a workqueue worker that obtains its context via container_of(work, struct T, work_member) and later uses complete() and/or kfree() on that context, with or without a completion_done() guard.
  - Scheduling role: a function that allocates/uses a context struct T, schedules its work, waits with wait_for_completion_timeout(), and frees the context on the timeout path.
- checkEndAnalysis: Correlate the collected worker and scheduling information by struct type T and emit a report if we find a scheduling function that frees on timeout and a worker for the same T that uses the context without a completion_done() guard.

3. Data to collect (checker member data, not ProgramState)
- For workers (keyed by RecordName, i.e., struct tag name):
  - RecordName: string (e.g., "adf_reset_dev_data") taken from the pointee type of the variable initialized via container_of.
  - CtxVarName: string, the local variable name holding the context pointer (e.g., "reset_data"). Used to match calls.
  - HasCompletionDoneGuard: bool. True if the function calls completion_done(&ctx->compl).
  - UsesCompleteOrKfree: bool. True if it calls complete(&ctx->compl) or kfree(ctx).
  - AnyUseLoc: SourceLocation for an unguarded action (complete()/kfree()) to reference in diagnostics if needed.

- For schedulers (keyed by RecordName):
  - RecordName: string (same as above).
  - HasQueueWorkWithSameCtx: bool. True if the function calls queue_* or schedule_* APIs with &ctx->work for the same ctx variable.
  - HasWaitTimeoutOnSameCtx: bool. True if it calls wait_for_completion_timeout(&ctx->compl) for the same ctx variable.
  - FreesCtxOnTimeout: bool. True if there is a kfree(ctx) in a path that may correspond to timeout.
  - FreeLoc: SourceLocation of the suspicious kfree(ctx).

Implementation details:

4. checkASTCodeBody: Worker role detection (per function)
- Step W1: Detect container_of context extraction.
  - Find a DeclStmt with a VarDecl of pointer-to-RecordType whose initializer source contains "container_of" (use ExprHasName on the initializer).
  - Extract:
    - RecordName: from the VarDecl’s pointee RecordType (getDecl()->getNameAsString()).
    - CtxVarName: from the VarDecl’s name.
  - If not found, this function is not a worker; return.

- Step W2: Scan the function body for calls that refer to the same context.
  - For each CallExpr:
    - Identify callee by name via CallEvent/IdentifierInfo or callee FunctionDecl:
      - completion_done:
        - Check if the first argument is &ctx->compl:
          - Use findSpecificTypeInChildren<MemberExpr>(Arg0) and validate:
            - The base of the MemberExpr is a DeclRefExpr matching CtxVarName.
          - If matched, set HasCompletionDoneGuard = true.
      - complete:
        - Check if the first argument is &ctx->compl (same way as above). If matched, set UsesCompleteOrKfree = true. If HasCompletionDoneGuard is false at this point, keep the Call’s location as AnyUseLoc (first occurrence).
      - kfree:
        - Check if the first argument is a DeclRefExpr matching CtxVarName. If matched, set UsesCompleteOrKfree = true and record AnyUseLoc if not set.

- Step W3: Store WorkerInfo[RecordName]:
  - RecordName
  - HasCompletionDoneGuard
  - UsesCompleteOrKfree
  - AnyUseLoc

5. checkASTCodeBody: Scheduling role detection (per function)
- Step S1: Detect wait_for_completion_timeout on a context.
  - For each CallExpr to wait_for_completion_timeout:
    - Extract the first argument; ensure it’s &X->compl (MemberExpr under UnaryOperator ‘&’):
      - Get the MemberExpr and its base DeclRefExpr; the base variable name is X.
      - Extract RecordName from the base’s type (pointer to record).
    - If found, set HasWaitTimeoutOnSameCtx = true for this RecordName in this function.

- Step S2: Detect that the same function schedules the worker on the same context.
  - Look for calls to queue_work, queue_delayed_work, schedule_work, schedule_delayed_work, etc.:
    - Check if any argument is &X->work for the same base ctx variable X (MemberExpr under ‘&’ and member name contains “work”).
    - If found, set HasQueueWorkWithSameCtx = true.

- Step S3: Detect that ctx is freed on the timeout path.
  - Primary pattern (If-statement around the wait):
    - Find an enclosing IfStmt where the condition contains “wait_for_completion_timeout” (ExprHasName).
    - Heuristics to decide which branch is timeout:
      - If the condition is a UnaryOperator ‘!’ over the call, then the ‘then’ branch is timeout.
      - If the condition is BinaryOperator ‘== 0’ with the call on one side, then the ‘then’ branch is timeout.
      - If the condition is just the call (no negation), then the ‘else’ branch is timeout (i.e., call returns 0 -> timeout).
    - In the identified timeout branch, search for kfree(X) where the argument is DeclRefExpr matching X. If found, set FreesCtxOnTimeout = true and FreeLoc = that call’s location.

  - Secondary pattern (unconditional or later free after the If):
    - If an IfStmt condition contains wait_for_completion_timeout and neither branch returns, scan the subsequent sibling statements in the same CompoundStmt for kfree(X).
      - Use findSpecificTypeInParents to get the parent CompoundStmt of the IfStmt, iterate statements after it; if any kfree(X) is found, treat it as “potentially after timeout” and set FreesCtxOnTimeout = true and FreeLoc accordingly.

- Step S4: Store SchedulingInfo[RecordName] for this function only if:
  - HasWaitTimeoutOnSameCtx == true
  - HasQueueWorkWithSameCtx == true
  - FreesCtxOnTimeout == true

6. checkEndAnalysis: Correlate and report
- For each RecordName that appears in both:
  - WorkerInfo[RecordName] with:
    - UsesCompleteOrKfree == true
    - HasCompletionDoneGuard == false
  - and SchedulingInfo[RecordName] with:
    - FreesCtxOnTimeout == true
  - Emit a BasicBugReport:
    - Short message: “Workqueue context may be freed on timeout while worker still uses it; missing completion_done() guard.”
    - Primary location: SchedulingInfo[RecordName].FreeLoc (the kfree on timeout).
    - Optionally, add a note pointing to WorkerInfo[RecordName].AnyUseLoc if available (complete()/kfree() use in worker).

7. Utilities and matching details
- Use ExprHasName to:
  - Detect “container_of” usage in the worker’s initializer expression.
  - Detect “wait_for_completion_timeout” in If conditions.
- Use findSpecificTypeInChildren to extract MemberExpr from call arguments and verify:
  - Base is DeclRefExpr whose name equals the ctx variable name we’re tracking.
  - Member name equals or contains “compl” for completion and “work” for the work_struct field.
- Use getNameAsString/getDecl()->getNameAsString on RecordType to derive RecordName in a normalization form (e.g., without “struct ” prefix).
- Recognized API names (callee identifiers):
  - Worker side: completion_done, complete, kfree.
  - Scheduler side: wait_for_completion_timeout, queue_work, schedule_work, queue_delayed_work, schedule_delayed_work.

8. Reporting policy
- Report only when both sides match on RecordName: this keeps false positives low.
- Do not attempt path-sensitive ownership proofs; rely on the clear syntactic pattern: wait_for_completion_timeout + timeout-free on scheduler side, combined with missing completion_done() check in the worker.

9. Notes and limitations
- The guard detection is conservative: if the worker calls completion_done(&ctx->compl) anywhere, we treat it as “guard present,” assuming it participates in gating the free/complete logic.
- The timeout-branch identification uses common idioms: if (wait_for_completion_timeout(...)) vs if (!...) and (== 0). If unusual forms appear, the secondary pattern (free after the If) still detects suspicious frees.
