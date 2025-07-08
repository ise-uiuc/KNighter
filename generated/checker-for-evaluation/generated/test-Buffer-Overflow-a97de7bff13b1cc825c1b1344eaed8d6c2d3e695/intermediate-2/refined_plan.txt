Your plan is as follows:

---------------------------------------------------------
1. Decide if it’s necessary to customize program states:
   • In this checker, you do not need to register any new program state maps (traits or pointer alias maps) because the bug pattern is solely based on detecting the use of a data‐copy routine without any preceding length validation. No pointer or alias tracking is required.

2. Choose the callback function:
   • Use the checkPreCall callback to intercept calls to data‐copy functions before they are executed.

3. Steps to implement the callback in checkPreCall:
   • In checkPreCall, inspect each CallEvent.
   • Use the call’s callee identifier (via Call.getCalleeIdentifier()) and compare its name against "copy_from_sockptr".
   • If the function name matches "copy_from_sockptr", then you have encountered a call where the fixed-size copy routine is used without an explicit check against the provided optlen.
   • Optionally, retrieve and evaluate the third argument (the fixed size used in the call) by calling EvaluateExprToInt. You can also check if the passed size is a compile-time constant by using utility methods (like EvaluateExprToInt); however, the essential pattern is that the proper length check is missing.
   • Since the fixed-size copying routine “copy_from_sockptr” is being used in lieu of “bt_copy_from_sockptr” (which checks that optlen is sufficient), report the bug.

4. Bug Reporting:
   • In checkPreCall, if the callee is "copy_from_sockptr", create a non-fatal error node.
   • Emit a bug report (using std::make_unique<BasicBugReport> or std::make_unique<PathSensitiveBugReport>) with a clear and short message such as: "User input length not validated before copying – potential slab buffer over-read".
   
5. Additional Note (Optional):
   • You could also hook into checkBranchCondition to see if an if statement exists that compares optlen with the expected size before the copy, but since the core bug pattern is misuse of copy_from_sockptr without any validation, directly flagging such calls in checkPreCall is the simplest solution.

---------------------------------------------------------
In summary, your plan uses checkPreCall to catch calls to copy_from_sockptr. By comparing the callee name and optionally evaluating the fixed copy size parameter, you can directly report a bug when the routine is used without prior validation of optlen. This approach is simple, follows the suggestions, and minimizes unnecessary state management.