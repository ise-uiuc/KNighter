Your plan is as follows:

1. Decide on Program State Customization:  
   • No customized program state or maps are necessary in this checker because the primary goal is to flag the use of unsafe string-copy functions when the destination buffer is fixed-size.  
   • Alias analysis or pointer tracking is not required for this simple check.

2. Choose Callback Functions:  
   • Use the checkPreCall callback to intercept every function call. Since strcpy is a standard function, checking right before the call is sufficient.  
   • Optionally, you could use checkASTDecl to identify declarations to determine fixed-size buffers, but instead you can simply check the destination expression at the call site using utility functions.

3. Detailed Implementation Steps:

   Step 1. In checkPreCall, intercept all call events.  
     • Verify the callee’s name using the helper (for example, by calling the ExprHasName utility or comparing Call.getCalleeIdentifier()->getName() with "strcpy").  
     • If the call is not to strcpy, return early.

   Step 2. Analyze the destination argument:  
     • Retrieve the destination expression from the call arguments (the first parameter for strcpy).  
     • Use the utility function getArraySizeFromExpr to check if this destination is a fixed-size array.  
     • If getArraySizeFromExpr returns true, then you have confirmed that the destination is a statically sized buffer.

   Step 3. Check for Unsafe Use:  
     • Since strcpy does not permit specifying the buffer size, report a bug immediately if the destination is fixed-size.  
     • You might also use getStringSize on the source argument if it is a string literal; however, the unsafe behavior is already evident from using strcpy without bounds check regardless of source length.
   
   Step 4. Emit a Bug Report:  
     • Use generateNonFatalErrorNode or directly create a bug report (using std::make_unique<PathSensitiveBugReport> or std::make_unique<BasicBugReport>) if the check detects an unsafe use of strcpy.
     • The report message should be short and clear (e.g., "Unsafe use of strcpy on fixed-size buffer may lead to overflow").

4. Summary:  
   • The checker uses checkPreCall to detect a call to strcpy.  
   • The destination argument is validated using getArraySizeFromExpr to ensure it is a fixed-size buffer.  
   • If an unsafe pattern is detected, a bug report is generated.  

This simple, concrete plan should allow you to implement the checker with minimal steps while relying on the provided utility functions.