Your plan is as follows:

----------------------------------------------------------------
1. Customize a program state map

• REGISTER a program state map (e.g., PtrStateMap) that maps a pointer’s memory region (const MemRegion *) to a state flag (bool).  
• The flag will be false when the pointer is “live” (or has been reinitialized to NULL) and set to true once the pointer value has been freed.  
• This map will allow tracking the “ea” pointer across different execution paths (replay loops).

----------------------------------------------------------------
2. Add a call hook for freeing (checkPreCall)

• In checkPreCall, detect call events to the deallocation function “kfree”.  
• Use the callee name (compare with literal "kfree") to filter the function.  
• Retrieve the first argument of the kfree call and obtain its memory region using getMemRegionFromExpr.  
• Look up that region in PtrStateMap:
  – If the region is already flagged true, report a warning (“Double free of ea pointer”) using a bug report (e.g. via std::make_unique<BasicBugReport>).  
  – Otherwise, update the program state by marking the region as true (i.e. freed).

----------------------------------------------------------------
3. Track pointer reinitialization (checkBind)

• Use checkBind to catch bindings involving our “ea” variable.  
• When the checker sees an assignment where the left-hand side refers to “ea” (e.g. the source text contains “ea”) and the right-hand side is a NULL literal, update the program state:  
  – Retrieve the pointer’s region from the left-hand side using getMemRegionFromExpr.  
  – Reset the flag in PtrStateMap to false (indicating that “ea” has been reinitialized and is safe for later free).  
• If aliasing exists, update all entries in a PtrAliasMap accordingly (using REGISTER_MAP_WITH_PROGRAMSTATE if necessary).

----------------------------------------------------------------
4. Overall flow summary

• The checker will record that “ea” has been freed (flagged true) in checkPreCall when kfree is called.  
• On subsequent executions (e.g. in a replay loop), if the pointer “ea” has not been reinitialized to NULL (detected via checkBind), then another call to kfree will find that the region is still flagged as freed.  
• At that moment, emit a short, clear bug report about the risk of a double free.

----------------------------------------------------------------
5. Final remarks

• Use the provided utility functions (e.g., getMemRegionFromExpr and EvaluateExprToInt) to simplify the implementation.  
• Only track the specific “ea” pointer by checking the expression source text (via ExprHasName) or similar means in checkBind.  
• Ensure that your bug report message is short and clear (e.g. “Double free of ea pointer detected”).

Following these concrete steps should allow you to write a concise checker to detect the failure to reinitialize “ea” after freeing it, which leads to a potential double free vulnerability.