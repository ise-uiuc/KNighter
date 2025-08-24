Plan

1. Program state customizations
- REGISTER_MAP_WITH_PROGRAMSTATE(CompUseMap, const MemRegion*, unsigned)
  - Bitmask per context base-region:
    - SEEN_COMPLETE = 0x1  // complete(&ctx->compl) observed
    - SEEN_KFREE    = 0x2  // kfree(ctx) observed
    - SEEN_DONE     = 0x4  // completion_done(&ctx->compl) observed
- REGISTER_MAP_WITH_PROGRAMSTATE(CompLastUseStmt, const MemRegion*, const Stmt*)
  - Keep a source location (Stmt*) for the last interesting call (complete or kfree) for bug reporting.

Note: Keep the state strictly intra-procedural. No need to persist across functions. To reduce false positives, also keep a checker member flag:
- bool SawTimedWaitInTU = false  // Set true if we ever see wait_for_completion_timeout anywhere; used as a TU-wide heuristic gate.

2. Callback selection and implementation details

A. checkBeginFunction(Ctx)
- Purpose: Identify worker functions and initialize per-function state (implicit, as maps start empty).
- Implementation:
  - Determine if the current function is a worker by inspecting its parameters:
    - Iterate FunctionDecl->parameters, and if any parameter’s pointee record name equals "work_struct" (i.e., param type is struct work_struct *), mark a local flag IsWorkerFn = true for this invocation. No need to store in program state; you can recompute in checkEndFunction by querying the FunctionDecl again.

B. checkPostCall(const CallEvent &Call, CheckerContext &C)
- Purpose: Track the use of completion, timeout waits, and frees.
- Extract callee name with Call.getCalleeIdentifier()->getName().
- Handle the following functions:

  1) wait_for_completion_timeout
     - If callee name equals "wait_for_completion_timeout", set SawTimedWaitInTU = true.
     - If first argument is a completion expression like &ctx->compl:
       - Retrieve base region B of the completion’s base expression using:
         - If Arg0 is UnaryOperator(&) over MemberExpr (ctx->compl), use MemberExpr->getBase() and getMemRegionFromExpr to obtain B.
       - No need to set any flags here; we only globally gate on SawTimedWaitInTU.

  2) complete
     - If callee name equals "complete":
       - If Arg0 is &ctx->compl, obtain base region B as above.
       - Update CompUseMap[B] |= SEEN_COMPLETE.
       - Record CompLastUseStmt[B] = Call.getOriginExpr() (or Call.getStmt()) for reporting.

  3) completion_done
     - If callee name equals "completion_done":
       - If Arg0 is &ctx->compl, obtain base region B similarly.
       - Update CompUseMap[B] |= SEEN_DONE.

  4) kfree
     - If callee name equals "kfree":
       - Obtain base region B from Arg0 (the ctx pointer) using getMemRegionFromExpr.
       - Update CompUseMap[B] |= SEEN_KFREE.
       - Record CompLastUseStmt[B] = Call.getOriginExpr() (or Call.getStmt()).

Notes:
- Robustly extract B:
  - For complete/completion_done: expect Arg0 to be a UnaryOperator taking address of a MemberExpr; use the MemberExpr->getBase() as the ctx expression and call getMemRegionFromExpr on it.
  - For kfree: directly call getMemRegionFromExpr on Arg0.
- Ignore cases where B is null (unknown region).

C. checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
- Purpose: At function exit, decide whether to report based on the aggregated info in CompUseMap for this function.
- Steps:
  - Confirm the current function is a worker: inspect FunctionDecl parameters to see if it has struct work_struct * parameter.
  - If not a worker, return early.
  - Optionally reduce noise: if SawTimedWaitInTU == false, return early (we only warn when the translation unit uses wait_for_completion_timeout somewhere).
  - Iterate over CompUseMap entries. For each base region B:
    - Let Flags = CompUseMap[B].
    - If (Flags & (SEEN_COMPLETE | SEEN_KFREE)) != 0 AND (Flags & SEEN_DONE) == 0:
      - This worker either completes or frees the shared context but never guards with completion_done(). This is the dangerous pattern when submitter times out.
      - Create a non-fatal error node and emit a PathSensitiveBugReport at the location CompLastUseStmt[B] if present; otherwise at function location.
      - Message: Missing completion_done() guard in worker; submitter with timed wait may free the context.
- Clear maps implicitly as function state ends.

3. Optional enhancement (low-cost heuristic to catch submitter misuse)
- In the same checkPostCall, track a lightweight submitter anti-pattern in-function (does not require path reasoning):
  - If we see a wait_for_completion_timeout(&ctx->compl, ..) and later in the same function we see kfree(ctx), and there is no subsequent call to completion_done(&ctx->compl) in the same function:
    - This suggests the submitter frees the context after a timed wait without coordination.
    - You can report a lower-severity warning in checkEndFunction for non-worker functions:
      - Message: Context freed after wait_for_completion_timeout(); ensure worker guards with completion_done() or free only on success.
- This step is optional; keep it off by default to minimize noise.

4. Utilities used
- getMemRegionFromExpr to map expressions to MemRegion for stable identification of the shared context pointer.
- findSpecificTypeInParents / findSpecificTypeInChildren not strictly necessary here.
- ExprHasName not needed; we rely on callee names.
- EvaluateExprToInt and inferSymbolMaxVal not needed.

5. Reporting
- Create a single BugType at checker construction time (e.g., "Workqueue timed-wait UAF risk").
- Use generateNonFatalErrorNode to create a node and std::make_unique<PathSensitiveBugReport> for reporting.
- Keep the message short and clear:
  - "Missing completion_done() guard in worker; submitter with timed wait may free the context"
- Attach a range to the offending call (kfree or complete) using CompLastUseStmt[B].

Why this detects the target pattern
- The bug arises when a worker completes or frees a shared context while the submitter might have timed out and already freed that context. The kernel fix added completion_done() checks before choosing between complete() and kfree(), exactly what this checker enforces.
- Restricting to worker functions (struct work_struct * parameter) and requiring that the TU uses wait_for_completion_timeout keeps false positives low while matching the scenario in the patch.
