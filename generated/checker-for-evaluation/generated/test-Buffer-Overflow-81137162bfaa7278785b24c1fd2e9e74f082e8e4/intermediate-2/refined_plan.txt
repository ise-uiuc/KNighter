Your plan here

1. Callback Selection:  
   • Use checkPreCall to intercept all call events.  
   • No need to customize program state or alias maps since pointer aliasing is not a concern for this check.

2. In checkPreCall:  
   • First, check if the CallEvent’s callee identifier is "strcpy". If it is not, do nothing.  
   • Retrieve the arguments from the call event:  
  – The first argument is the destination buffer.  
  – The second argument is the source string.

3. Validate the Destination Buffer:  
   • Use the utility function getArraySizeFromExpr on the destination argument to determine if it is a fixed-size array.  
   • If getArraySizeFromExpr fails (i.e. the destination is not a proper fixed-size array), then skip further checking.

4. Examine the Source String:  
   • Attempt to retrieve the length of the source string using getStringSize.  
   • If getStringSize succeeds, compare the obtained string length with the destination’s fixed array size.  
   • If the source string size is greater than or equal to the destination size, this indicates a potential buffer overflow.  
   • If getStringSize fails (for instance, if the source is not a string literal), you may opt to be conservative and report a warning since the size cannot be verified.

5. Report the Bug:  
   • If the unsafe usage is detected (i.e. copying a possibly oversized source into a fixed-size destination without bounds), generate a bug report.  
   • Use a short, clear message such as “Unsafe use of strcpy may cause buffer overflow.”  
   • Create the report using std::make_unique<BasicBugReport> or std::make_unique<PathSensitiveBugReport> and emit it using the CheckerContext.

By following these concrete steps in the checkPreCall callback and using the provided utility functions for array and string size resolution, you can implement a simple yet effective checker for detecting the unsafe use of strcpy that may lead to a buffer overflow.