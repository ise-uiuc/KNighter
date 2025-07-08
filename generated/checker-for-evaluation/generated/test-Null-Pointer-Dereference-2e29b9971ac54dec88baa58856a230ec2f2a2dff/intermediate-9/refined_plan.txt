Your plan here

1. Decide on Program State Customization:
   • In this checker the bug is not about tracking value flows over many functions but about detecting a mismatch between the allocated field and the pointer being checked. Therefore, no custom program state map is strictly required.

2. Choose and Implement Callback Functions:

   • Use checkBranchCondition:
     - In checkBranchCondition, intercept every if-condition.
     - For each condition, use the helper function ExprHasName to check if the condition’s source text contains the field name "thread.za_state" (i.e. the field being null-checked).
     - If the condition involves a null-check on "thread.za_state", then proceed to step 3.

   • Use checkPostCall:
     - In checkPostCall, intercept calls to kzalloc.
     - When you detect a call to kzalloc, use AST traversal (or simple string matching on the callee's name) and the utility functions (for example, ExprHasName) on its parent assignment to verify that the allocation result is being assigned to "thread.sve_state".
     - Record that a kzalloc call has been made for "thread.sve_state" in the current function.

3. Cross-Check Allocation and Null-Check:
   • Within the scope of a function (or a suitable enclosing AST node), if checkBranchCondition identified a null-check on "thread.za_state", then check (using the AST search from checkPostCall) whether an earlier kzalloc call was used to allocate "thread.sve_state".
   • If a kzalloc call to allocate "thread.sve_state" exists while the null-check is performed on "thread.za_state", then this is our bug pattern.

4. Report a Bug:
   • When the above mismatch is detected, use a bug-report creation utility (e.g., std::make_unique<PathSensitiveBugReport> or std::make_unique<BasicBugReport>) to emit a concise report: for example, "Null check is performed on wrong pointer; expected check on thread.sve_state".
   • Generate a non-fatal error node and attach the bug report.

5. Additional Considerations:
   • Use AST upward/downward traversal utilities such as findSpecificTypeInParents or findSpecificTypeInChildren if needed to locate the assignment or call expressions relative to the branch condition.
   • Keep the implementation as simple as possible by focusing on string comparisons via ExprHasName to identify the targeted field names in both the allocation assignment and the null-check condition.

By following these detailed steps in the callbacks using the provided utility functions, you can write a checker that detects when memory allocated with kzalloc (for thread.sve_state) is improperly checked (the check is on thread.za_state instead).