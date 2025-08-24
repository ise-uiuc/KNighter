Plan to detect “work context freed by submitter after timeout while worker still uses it” (missing completion_done() guard)

1) Program state customization
- No custom program state is strictly necessary. This pattern can be identified with AST-centric scans and minimal heuristics.
- Do not register any ProgramState maps by default. Keep it simple and focus on two complementary AST checks:
  - Worker-side: work handler uses the context (complete()/kfree()) without a completion_done() guard.
  - Submitter-side: submitter frees the context in the timeout branch right after wait_for_completion_timeout().

2) Callback functions and how to implement

A. checkASTCodeBody: worker-side detection (primary and simplest, no state)
Goal: In a work handler (void f(struct work_struct *)), detect:
- The handler derives a context from work via container_of(work,...).
- It calls complete(&ctx->compl) and/or kfree(ctx).
- It does not call completion_done(&ctx->compl) anywhere in the handler.
This indicates the worker is unaware of submitter timeout and may access/free a context that the submitter already freed.

Steps:
1. Identify a work handler:
   - For each FunctionDecl D with a body, check if the first parameter exists and its QualType pretty string contains "work_struct *" (or is a pointer to ‘struct work_struct’).
   - Record the parameter name, e.g., "work".
2. Heuristically derive the “context variable” name:
   - Traverse all local variable declarations (VarDecl with init).
   - If the initializer’s source (ExprHasName) contains both the work parameter name and "container_of", treat this VarDecl as the “ctx” variable candidate.
   - If multiple candidates exist, pick the first one; store its IdentifierInfo()->getName() as CtxName.
   - If no local that looks like container_of is found, as a fallback, still try to detect complete(&X->compl) and completion_done(&X->compl) calls whose arguments don’t mention "work" but consistently mention one variable name; pick that as CtxName.
3. Scan for uses:
   - Walk all CallExpr in the function body:
     - If callee identifier is "complete" or "complete_all":
       - Let Arg0 be the call’s first argument. If ExprHasName(Arg0, CtxName) and ExprHasName(Arg0, "compl"), mark UsedComplete = true.
     - If callee identifier is "kfree":
       - If the single argument’s text ExprHasName(Arg0, CtxName), mark UsedKfree = true.
     - If callee identifier is "completion_done":
       - If Arg0 mentions both CtxName and "compl", mark HasGuard = true.
4. Report:
   - If (UsedComplete || UsedKfree) && !HasGuard, report a bug at the function location:
     - Message: "work handler lacks completion_done() guard before using/freeing shared context"
   - Use a BasicBugReport or PathSensitiveBugReport (the AST code body callback is fine for a basic report).
Notes:
- Rely on ExprHasName to match source substrings such as “ctx->compl”, “&ctx->compl”. This keeps the logic simple and robust in kernel macro-heavy code.
- This directly flags the missing guard that caused the real UAF.

B. checkBranchCondition: submitter-side detection (secondary, low false-negative heuristic)
Goal: In a submitter function, detect freeing the work-item context in the timeout branch after wait_for_completion_timeout(&ctx->compl, …), while the worker may still use it.
We purposefully focus on the “if (!wait_for_completion_timeout(...)) { kfree(ctx); }” pattern.

Steps:
1. On each branch condition, check for the pattern of negated wait:
   - If Condition is a UnaryOperator '!' whose subexpr is a CallExpr Call.
   - Check that the callee identifier is "wait_for_completion_timeout".
2. Extract the context from the wait call:
   - From Call’s first argument Arg0 (the completion), try to peel “&ctx->compl”:
     - If Arg0 is a UnaryOperator ‘&’ of a MemberExpr ME:
       - If ME’s name contains "compl" (use ExprHasName(ME, "compl")), then ME->getBase() is the expression for “ctx”.
       - If ME->getBase() is a DeclRefExpr, get ctx variable name (CtxName).
     - If the exact shape differs, fallback to source heuristics:
       - Get text of Arg0 using ExprHasName and attempt to find the token before “->compl” to identify the variable. If not possible, skip to avoid FPs.
3. Find the IfStmt corresponding to the condition:
   - Use findSpecificTypeInParents<IfStmt>(Condition, C) to get the owning IfStmt IfS.
   - The “then” branch of IfS corresponds to timeout (because it’s the negated call).
4. Search for kfree(ctx) in the timeout branch:
   - Use findSpecificTypeInChildren<CallExpr>(IfS->getThen()) to get a child call (note: helper returns only one; if not kfree, recursively scan children manually if desired. For simplicity: if the first call found is kfree with argument containing CtxName, flag. If not, iterate shallowly over compound children to find kfree).
   - When you find CallExpr with callee "kfree" and argument contains CtxName (ExprHasName), record FoundTimeoutFree = true.
5. Optionally, ensure this context is a work item context:
   - In the same function body, search for a queue_work family call that uses &ctx->work:
     - Look for CallExpr callee "queue_work" (or "queue_delayed_work" etc. if desired).
     - Check if any argument contains both CtxName and "work" (ExprHasName(arg, CtxName) && ExprHasName(arg, "work")).
     - If found, mark QueuedWork = true.
6. Report:
   - If FoundTimeoutFree is true and QueuedWork is true, report:
     - Message: "frees work context on timeout while worker may still use it"

C. Optional: checkASTCodeBody: submitter unconditional free after wait
To partially catch the specific variant where the free happens unconditionally after the if:
1. In function body, search for a CallExpr to wait_for_completion_timeout as in B. Extract CtxName.
2. After locating that IfStmt with condition of either “!wait_for_completion_timeout(...)” or “wait_for_completion_timeout(...)”:
   - Look for any kfree(ctx) in the sibling/next statements (e.g., in the same compound block following the IfStmt). A simple heuristic:
     - Get the CompoundStmt that contains the IfStmt (findSpecificTypeInParents<CompoundStmt>).
     - Iterate its children after the IfStmt node; if any kfree call’s arg mentions CtxName, then report the same warning as in B.
3. Again optionally gate on having observed queue_work(..., &ctx->work) earlier in the function.

3) Reporting
- Use generateNonFatalErrorNode() and std::make_unique<PathSensitiveBugReport> for branch-based report in checkBranchCondition; or std::make_unique<BasicBugReport> in checkASTCodeBody if not relying on path.
- Keep messages short:
  - Worker: "work handler lacks completion_done() guard before using/freeing shared context"
  - Submitter: "frees work context on timeout while worker may still use it"

4) Helper utilities used
- ExprHasName to match substrings like "container_of", variable names, "->compl", "&...".
- findSpecificTypeInParents<IfStmt> to locate the enclosing IfStmt from a condition in checkBranchCondition.
- findSpecificTypeInChildren<CallExpr> to search for kfree in the then-branch (best-effort).
- Optionally, EvaluateExprToInt is not required here.
- getMemRegionFromExpr is not required in the simplified approach.

5) Summary of the simplest actionable steps
- Implement worker-side AST scan in checkASTCodeBody, as it pinpoints the missing completion_done() guard which is the root cause in the worker.
- Implement submitter-side timeout-free detection via checkBranchCondition for the common pattern “if (!wait_for_completion_timeout(&ctx->compl, ...)) kfree(ctx);” with an optional confirmation that queue_work(..., &ctx->work) appears in the same function.
- Optionally, catch unconditional free after the if by scanning sibling statements in checkASTCodeBody.
