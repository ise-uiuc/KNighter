Your plan is as follows:

------------------------------------------------------------
1. Decide if customization of program state is necessary:
   • No program state maps are required here since we only need to detect a redundant cleanup call by comparing callee names and AST contexts.

2. Choose the callback to hook:
   • Use the checkPreCall callback to intercept any call to scmi_debugfs_common_cleanup.
   • Use the checkBranchCondition callback or AST traversal within checkPreCall to determine if the cleanup call is inside an error handling branch where devm_add_action_or_reset has already been invoked.

3. Implementation steps per callback:

   (a) In checkPreCall:
       • When a call is intercepted, check if its callee’s name is "scmi_debugfs_common_cleanup".
       • Once such a call is identified, use the utility function findSpecificTypeInParents to climb up the AST and locate a parent IfStmt.
       • Retrieve the condition expression of that IfStmt.
       • Use the utility function ExprHasName on the condition expression to verify if it contains the call to devm_add_action_or_reset.
           ▪ This indicates that the branch corresponds to the error path where devm_add_action_or_reset was evaluated.
       • If the above check passes, report a bug with a clear and short message indicating that there is a redundant cleanup call that may cause a double free.

   (b) (Optional) In checkBranchCondition:
       • Alternatively (or in addition) you could use this callback to review the condition of an if statement.
       • Look for the appearance of devm_add_action_or_reset in the condition.
       • Flag the branch as suspicious and possibly annotate its state.
       • Then, in checkPreCall for cleanup calls, consult this flag.
       ▪ This step is optional since the combined check in checkPreCall using the parent AST traversal should be sufficient.

4. Reporting the bug:
   • Generate the error node and a bug report using std::make_unique<BasicBugReport> or std::make_unique<PathSensitiveBugReport>.
   • The report message should be short and clear, e.g., "Redundant cleanup call leads to double free."

------------------------------------------------------------
Follow these steps to write the checker. This plan uses the provided utility functions for AST navigation and name checking, avoids extraneous program state management, and implements the checker in just two main logical steps.