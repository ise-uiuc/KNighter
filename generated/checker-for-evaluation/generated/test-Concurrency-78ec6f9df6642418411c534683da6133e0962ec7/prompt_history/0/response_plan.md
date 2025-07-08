Your plan here

1. Decide on Program State  
• No new program state maps are needed for this pattern. We are only concerned with flagging non‐atomic updates on a specific field (“stats_updates”) that are not using the correct atomic primitives.  
• We do not need alias tracking for this simple pattern.

2. Choose Callback Function  
• Use the checkBind callback. This callback is invoked when a value is bound to a location. In this checker we want to intercept the assignment (or compound assignment) to a member field named “stats_updates.”

3. Implementation in checkBind  
• In checkBind, first retrieve the source range or text of the statement (using something like ExprHasName) associated with the left-hand side (i.e. the location S) to determine if it accesses “stats_updates.”  
• To do this, call the utility function ExprHasName on the left-hand side expression with the string "stats_updates". If it returns true, then we have identified an assignment or update to that counter.  
• Next, inspect the corresponding right-hand side (RHS) expression. Use the source text of the whole binding (or extract the RHS expression) and check whether the text includes either "READ_ONCE" or "WRITE_ONCE". You can use ExprHasName to search for these substrings.  
• If the RHS does not contain any occurrence of "READ_ONCE" or "WRITE_ONCE", then the update is a non-atomic read-modify-write pattern on the shared per-CPU counter.  
• In this case, use generateNonFatalErrorNode (or similar) and create a PathSensitiveBugReport (e.g. via std::make_unique<BasicBugReport>) to report a bug with a short message such as “Non-atomic update on per-CPU stats_updates.”

4. Reporting  
• Make sure the bug message clearly indicates that a read-modify-write operation on stats_updates is being performed without atomic macros, which risks a data race.  
• Emit the report immediately from the checkBind callback.

Summary Steps  
• In checkBind, examine every binding operation.  
• Use ExprHasName to check if the left-side reference involves “stats_updates.”  
• Check the source text of the corresponding assignment for “READ_ONCE” or “WRITE_ONCE.”  
• If not found, report the potential bug as a non-atomic update of a per-CPU counter causing a data race.

This simple, few-step plan directly hooks the binding of “stats_updates” and inspects the update expression text, ensuring that it follows the pattern of atomic access.