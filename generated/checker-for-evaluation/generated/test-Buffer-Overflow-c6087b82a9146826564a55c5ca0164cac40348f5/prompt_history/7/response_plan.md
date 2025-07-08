Your plan is as follows:

1. No need to customize or register any new program state maps in this simple case since you only need to analyze the arguments of copy_from_user() without tracking pointer aliasing.

2. Use the checkPreCall callback to inspect every function call:
   - In checkPreCall, detect calls to copy_from_user() by checking if the callee’s identifier equals "copy_from_user".
   - Retrieve the destination argument (the first argument) and the length argument (the third argument) from the CallEvent.

3. For the destination argument:
   - Use the utility function getArraySizeFromExpr() to attempt to obtain the fixed size of the destination buffer.
   - If the destination is not derived from a statically sized array or getArraySizeFromExpr() fails, then do not proceed with further analysis.

4. For the length argument:
   - Use EvaluateExprToInt() on the third argument (nbytes) to get its integer value.
   - Note that if evaluation fails, you can safely skip the check.

5. Compare the evaluated nbytes value against the buffer size:
   - Compute the maximum permissible copy size as (buffer_size - 1), following the referenced patch.
   - If nbytes is greater than (buffer_size - 1), then report a bug.

6. Report the Bug:
   - Generate an error node and create a bug report using std::make_unique<PathSensitiveBugReport> or std::make_unique<BasicBugReport>.
   - The report message should be short and clear (for example, “Potential buffer overflow: user-supplied length exceeds destination buffer capacity”).
   - Finally, use the CheckerContext’s emitReport() to output the bug.

Following these steps in the checkPreCall callback will allow you to catch when copy_from_user() is used with a user-supplied length that can lead to a buffer overflow.