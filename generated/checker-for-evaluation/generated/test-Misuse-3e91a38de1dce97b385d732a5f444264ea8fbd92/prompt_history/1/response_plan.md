Your plan for this checker is as follows:

------------------------------------------------------------
1. No need for custom program states

• For this bug pattern there is no need to track pointer aliasing or the initialization state via the program state. The issue concerns using the wrong API for array copy (memdup_user) without proper arithmetic overflow safeguards.

------------------------------------------------------------
2. Choose Callbacks

• Use the checkPreCall callback to intercept function calls. This callback lets you examine the callee’s name and its arguments before the function is executed.

------------------------------------------------------------
3. Implement checkPreCall

• In checkPreCall, retrieve the function name from the CallEvent by calling Call.getCalleeIdentifier() and then getNameAsString() to convert it into a string.
  
• Compare the retrieved function name with "memdup_user". If it equals, then you have found a potential bug point.

• (Optional) You can further check the context by verifying if the call occurs within the command case matching "VIAFB_SET_GAMMA_LUT" by traversing the AST upward (using findSpecificTypeInParents) and comparing the macro name (using getNameAsString on the relevant macro). This extra check can help reduce false positives.

------------------------------------------------------------
4. Report the Bug

• When a call to memdup_user is detected, generate a bug report by creating, for example, a BasicBugReport or PathSensitiveBugReport using std::make_unique.

• The bug report message should be short and clear, such as:
  "Using memdup_user for array copying may result in incorrect total size computation. Consider using memdup_array_user."

• Emit this report using the CheckerContext’s emitReport function.

------------------------------------------------------------
5. Summary

• No custom program-state maps (e.g., REGISTER_MAP_WITH_PROGRAMSTATE) are required.
• Use the checkPreCall callback to detect calls to memdup_user.
• If found, optionally verify that the call context involves user-supplied array copying (e.g. via checking that the parent switch statement’s case is the one for VIAFB_SET_GAMMA_LUT).
• Generate a clear, succinct bug report advising the use of memdup_array_user instead.

Following these steps should provide a straightforward and concise implementation for detecting the bug pattern.