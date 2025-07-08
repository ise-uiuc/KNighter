Your plan here

1. Decide if it’s necessary to customize program states:
   • No specialized program state maps (like PtrAliasMap) are needed because this bug pattern can be detected simply by examining the call to strcpy. We only need to check that the destination in a strcpy call is a fixed-size array.

2. Choose callback functions:
   • Use checkPreCall to intercept function calls.
   • (Optional) Use checkBind if you need to track aliasing of the destination, but for this simple checker that is not necessary.

3. Implementation details using checkPreCall:
   • In checkPreCall, filter for calls whose callee identifier is “strcpy”.
   • Once you intercept a strcpy call, extract the destination argument. Use the utility function getArraySizeFromExpr() on the destination argument to determine if it is a fixed-size array.
   • If getArraySizeFromExpr() returns true, that indicates that the destination is a fixed-size buffer.
   • At this point, report a bug. The message should be short and clear; for example: “Unbounded strcpy may overflow fixed-size destination buffer.”
   • Create the bug report using std::make_unique<PathSensitiveBugReport> or std::make_unique<BasicBugReport> and generate a non-fatal error node.
   • Do not use additional pointer tracking or alias analysis since the destination is directly retrieved and validated via getArraySizeFromExpr.

Following these steps will allow you to detect cases where strcpy is used to copy into a fixed-size array. This ensures that the checker warns when a bounded copy function (like strscpy) should be used to prevent potential buffer overflows.