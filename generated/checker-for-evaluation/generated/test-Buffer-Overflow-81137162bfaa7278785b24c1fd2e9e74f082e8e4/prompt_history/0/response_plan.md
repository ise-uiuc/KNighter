Your plan is as follows:

1. Decide if it’s necessary to customize program states:
   • For this checker, we do not need to define additional program-state maps (like PtrAliasMap or REGISTER_MAP_WITH_PROGRAMSTATE) because our analysis focuses only on detecting calls to strcpy. Simple call-event analysis is sufficient.

2. Choose callback functions:
   • Use checkPreCall to intercept and evaluate function call events.

3. Implement checkPreCall callback:
   • In checkPreCall, determine whether the called function has the name "strcpy".
   • Retrieve the first argument (destination) of the call.
   • Use the utility function getArraySizeFromExpr to attempt getting the fixed size of the destination array.
     - If getArraySizeFromExpr returns true, then a fixed-size buffer is being used.
   • Optionally, retrieve the source argument (second argument) of the call.
     - If the source is a string literal, use getStringSize to obtain its length. This gives extra confirmation if the literal might exceed the fixed size.
   • Decide if a potential vulnerability exists:
     - Either when the destination is a fixed-size array (size known) and the call is using strcpy (i.e., an unbounded string copy), or when the source literal (if available) is longer than the destination buffer.
   • If the condition is met, produce a concise bug report (“Unbounded string copy into a fixed-size buffer”) by creating a bug report node using std::make_unique<BasicBugReport> or PathSensitiveBugReport.

4. Report message:
   • Ensure that the report message is short and clear, and that it indicates that copying via strcpy into a fixed-size buffer can overflow the buffer.

This direct approach using checkPreCall and the provided utility functions will allow you to easily detect the bug pattern of using an unbounded string copy (strcpy) into a fixed-size buffer.