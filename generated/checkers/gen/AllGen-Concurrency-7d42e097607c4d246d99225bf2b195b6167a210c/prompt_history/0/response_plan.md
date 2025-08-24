Plan

1. Program state customization
- No custom program state is strictly necessary. We can detect this pattern locally by inspecting the AST around the if-condition that tests the result of wait_for_completion_timeout() and scanning the corresponding branches/siblings. This keeps the checker simple and robust.

2. Callback functions and detailed implementation steps

2.1 check::BranchCondition
Goal: Detect if-statements that branch on the result of wait_for_completion_timeout(), find the associated “work context” container, confirm that it was queued via queue_work(..., &ctx->work), and then detect kfree(ctx) in the timeout path or unconditional kfree(ctx) after the if.

Steps:
A. Identify a target if-statement
- Given the Stmt* Condition:
  - Find the enclosing IfStmt using findSpecificTypeInParents<IfStmt>(Condition, C). If none, return.
  - Determine whether the condition:
    1) Directly calls wait_for_completion_timeout(), or
    2) Tests a variable that was assigned the result of wait_for_completion_timeout() just before the if.

B. Case 1: Direct call in the condition
- Find the CallExpr under the condition using findSpecificTypeInChildren<CallExpr>(Condition).
- Check the callee name equals "wait_for_completion_timeout".
- Extract the first argument (completion pointer), which should look like &ctx->done or &ctx->compl:
  - Expect a UnaryOperator '&' whose subexpr is a MemberExpr.
  - From the MemberExpr base, extract the container “base variable” name (e.g., reset_data) via:
    - If base is a DeclRefExpr, use getDecl()->getNameAsString().
    - If base is another MemberExpr (e.g., foo->bar), get the top-most DeclRefExpr name. Fall back to using ExprHasName with the DeclRefExpr name on later checks.
  - Save BaseName string for matching kfree arguments.

- Determine which branch corresponds to the timeout path:
  - If the condition is UnaryOperator ‘!’ applied to the CallExpr, then Then-branch is the timeout path.
  - Else (no leading ‘!’), the Else-branch is the timeout path (because non-zero = completed; zero = timeout).

C. Case 2: Variable used in the condition (ret-pattern)
- The condition might be:
  - if (!ret), if (ret == 0), if (ret != 0), if (ret) etc.
- Extract DeclRefExpr from the condition using findSpecificTypeInChildren<DeclRefExpr>(Condition) to obtain VarName.
- Find the previous sibling statement of the IfStmt in its parent CompoundStmt:
  - Use findSpecificTypeInParents<CompoundStmt>(IfStmt, C) to get the block.
  - Iterate statements in the CompoundStmt to locate the IfStmt and identify its immediate predecessor.
  - Check if the previous statement assigns VarName = wait_for_completion_timeout(&ctx->done, ...):
    - Find an assignment with a CallExpr on the RHS to "wait_for_completion_timeout".
    - Extract BaseName as in Case 1 from the RHS first argument.
- Determine which branch is timeout based on the exact condition:
  - if (!ret) or if (ret == 0): Then-branch is timeout.
  - if (ret) or if (ret != 0): Else-branch is timeout.

D. Confirm the “work context” was queued earlier
- Reduce false positives by checking that, before this IfStmt in the same CompoundStmt (scan earlier siblings), there is a call to a queue_work-like function that uses the same BaseName for the work argument:
  - Look for calls named:
    - "queue_work", "queue_work_on", "queue_delayed_work", "queue_delayed_work_on".
  - For each candidate CallExpr, get the “work” argument (2nd param for queue_work, etc.) and check if it contains "&BaseName->work" (or any MemberExpr whose base contains BaseName and whose member contains "work"). Use ExprHasName on the argument with BaseName and "work".
- If no evidence of queue_work with &BaseName->work found, you may bail out to avoid FPs.

E. Search for kfree(ctx) in the timeout path
- Identify the timeout branch Stmt* (Then or Else) and recursively scan it for calls to "kfree" or "kvfree" whose first argument references BaseName:
  - Implement a small recursive walker (DFS) over the branch subtree to find CallExpr.
  - For each CallExpr with callee "kfree" or "kvfree", check if its first argument ExprHasName(arg, BaseName, C). If yes, mark FreeInTimeout = true.
- Also scan the non-timeout branch and mark FreeInSuccess if a matching kfree(ctx) is found.
- Additionally, detect unconditional free after the if:
  - From the parent CompoundStmt, iterate the statements following the IfStmt; recursively scan them for kfree/kvfree with BaseName. If found, mark FreeAfterIf = true.

F. Report conditions
- If FreeInTimeout && FreeInSuccess:
  - Report: "Freeing work context in both timeout and success paths"
- Else if FreeInTimeout:
  - Report: "Freeing work context on timeout after wait_for_completion_timeout()"
- Else if FreeAfterIf:
  - Report: "Unconditional free of work context after timed wait"
- Only report if step D confirmed a prior queue_work on the same BaseName; otherwise, skip.

G. Emitting the report
- Create a BugType once (e.g., "Uncoordinated free after timed wait").
- Use generateNonFatalErrorNode() and emit a PathSensitiveBugReport with a short message (as above). Use the kfree CallExpr location or the IfStmt as the report location for clarity.

2.2 Optional: check::PostCall (only if you want to support more forms)
- Not required by the core plan, but you can additionally record a simple map from variable symbols to BaseName when you see assignments "ret = wait_for_completion_timeout(&BaseName->done, ...)" so that in BranchCondition you don’t need to find the previous sibling assignment. This is optional and increases complexity. The core plan works with AST-local scanning in BranchCondition.

3. Helper functions you will write inside the checker
- bool isCallNamed(const CallExpr *CE, StringRef Name)
  - Match callee identifier name.
- bool extractBaseVarNameFromCompletionArg(const Expr *Arg, std::string &OutName)
  - Expect &ME; get MemberExpr ME; then extract DeclRefExpr base name.
- bool branchContainsFreeOfBaseName(const Stmt *S, StringRef BaseName, CheckerContext &C)
  - Recursively walk S; if CallExpr to kfree/kvfree with argument ExprHasName(arg, BaseName, C), return true.
- bool compoundHasQueueWorkWithBaseNameBefore(const CompoundStmt *CS, const IfStmt *IfS, StringRef BaseName, CheckerContext &C)
  - Iterate statements before IfS; recursively search for CallExpr to queue_* and check second argument contains both BaseName and "work".

4. Notes and simplifications
- This checker is intentionally local (AST-based) and does not rely on path-sensitive program state. It focuses on the typical kernel pattern:
  - queue_work(..., &ctx->work);
  - wait_for_completion_timeout(&ctx->done, ...);
  - kfree(ctx) in timeout branch or unconditionally after the if.
- Member names for the completion can be "compl"/"done"; the checker does not rely on the exact member name—only that it sees &BaseName->(any member) and correlates BaseName across queue_work, wait_for_completion_timeout, and kfree.
- Free functions checked: "kfree", "kvfree". You can extend with "vfree" if desired.
- The report messages should be short and clear, per Suggestions.

5. Summary of minimal callbacks used
- check::BranchCondition: Main logic to detect the pattern, correlate BaseName, confirm prior queue_work, and find kfree in timeout/success/after-if positions.
