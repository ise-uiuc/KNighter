Your plan here

1. Callback Selection – Use checkPreCall:
   • In the checkPreCall method, intercept every function call using the CallEvent.
   • Retrieve the callee’s identifier (its name) to determine if it is a legacy array-copy function.

2. Identification of Legacy Functions:
   • Check if the function name equals "memdup_user" or "vmemdup_user" (use getNameAsString() on the callee).
   • Optionally, if needed, use the utility function ExprHasName to inspect whether the source expression of the size argument contains "array_size", which indicates the size is computed using array_size().

3. Issue Warning Message:
   • Upon detection of a call to "memdup_user" or "vmemdup_user", generate a bug report with a short, clear message (e.g., "Legacy array-copy function used; use memdup_array_user/vmemdup_array_user instead").
   • Use std::make_unique<BasicBugReport> (or PathSensitiveBugReport) to create and emit the report.

4. Program State Customization:
   • In this checker, no additional program state maps (like REGISTER_MAP_WITH_PROGRAMSTATE) or pointer alias tracking is necessary because the issue is solely based on the use of legacy API names.
   • Therefore, there is no need to register a new program state.

5. Checker Implementation Summary:
   • In your checker’s checkPreCall method, retrieve the function’s name and compare against the target strings.
   • If a match is found, optionally search the call’s argument for the “array_size” macro using ExprHasName.
   • Immediately report the bug via generateNonFatalErrorNode and emit the bug report.
   • Keep the implementation simple by avoiding unnecessary state or pointer aliasing analysis.

This straightforward plan ensures that every call to legacy array-copy APIs is detected, and a clear warning is issued recommending the updated API usage.