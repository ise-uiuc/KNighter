Your goal is to detect a well‐known GCD performance antipattern where a semaphore (or a group) is used to “force synchrony” on a callback. The checker does not work in a flow‑sensitive manner—it simply checks for a compound AST pattern that ties together three pieces of code: the creation of a semaphore (or group), the signal (or leave) in a block, and finally a wait call on that semaphore (or group). Below is a concrete, step‑by‑step plan that explains how the checker works and what you need to implement.

────────────────────────────
Plan

1. Identify the core components to match:
   • The call that creates the semaphore (using dispatch_semaphore_create) or group (using dispatch_group_create).
   • A binding of the created semaphore (or group) into a variable. This is achieved by either finding a varDecl node having a descendant call to the create function or a binaryOperator that assigns the result of the create call to some variable. (The binding is given a name such as "semaphore_name" or "group_name".)
   • A call to a function that signals the semaphore (dispatch_semaphore_signal) or leaves the group (dispatch_group_leave) within a block (or message expression).
   • A corresponding wait call (dispatch_semaphore_wait or dispatch_group_wait) that uses as its argument the same variable that was bound earlier. You bind that wait call node (using a label like "waitcall") so you can later report an issue at that call.

2. Build the AST matchers using compound statements:
   • For the semaphore case:
     - Define a matcher (SemaphoreCreateM) that matches callExpr with function name "dispatch_semaphore_create" that is called with the literal integer 0.
     - Define a matcher (SemaphoreBindingM) that looks for a varDecl or assignment that “contains” the above create call and binds the creating variable (bind it with "semaphore_name").
     - Construct another matcher (HasBlockCallingSignalM) that finds a block (or objcMessageExpr) with an argument whose descendant callExpr matches dispatch_semaphore_signal with an argument equal to the bound semaphore.
     - Finally, build a matcher (SemaphoreWaitM) that looks for a callExpr to "dispatch_semaphore_wait" with its first argument equal to the bound semaphore. Bind this node with a name (WarnAtNode or "waitcall") so it can later be used for diagnostics.
   • For the group case, use a similar approach:
     - Create a matcher for dispatch_group_create.
     - Bind the variable holding the group using the varDecl or assignment approach (bind it with "group_name").
     - Match call expressions for dispatch_group_enter and for blocks containing dispatch_group_leave calls with arguments bound to the group.
     - Look for the wait call dispatch_group_wait that uses the same bound group and bind that node (again using "waitcall").

3. In the checkASTCodeBody callback:
   • First, check if the declaration being processed is a test (for example, a function or method beginning with "test" or inside a container with "test" or "mock"). If yes, skip the check.
   • Retrieve the AST body and run the semaphore matcher. For each match, extract the bound wait call node.
   • Run the group matcher in a similar fashion.
   • For each matched pattern (semaphore or group), call an emitDiagnostics helper function.

4. In emitDiagnostics:
   • Receive the BoundNodes that contain the wait call (bound as "waitcall").
   • Construct a clear diagnostic message explaining that waiting on a callback using a semaphore (or group) leads to poor performance or priority inversion issues.
   • Print the message along with the source location information (using the source range of the wait call node).

────────────────────────────
Summary of the Implementation Steps

• Step 1: Define and bind the creating function call (semaphore or group) and assign it to a variable.
• Step 2: Use AST descendant matchers to check that there is a block submitted to another function call where the created object is used in the signal (or leave) call.
• Step 3: Match the wait call (dispatch_semaphore_wait or dispatch_group_wait) that uses the same bound variable.
• Step 4: In checkASTCodeBody, reject mismatches (e.g., test cases) and then for every match, report a warning at the wait call node using diagnostic message from emitDiagnostics.

Following this step‑by‑step plan, you set up a compound AST matcher that identifies the antipattern and then easily report the issue. This approach keeps the checker simple while ensuring that each step is concrete and easy to follow.