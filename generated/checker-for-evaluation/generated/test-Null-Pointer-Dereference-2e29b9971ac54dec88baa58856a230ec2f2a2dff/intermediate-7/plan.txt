Your plan is as follows:

------------------------------------------------------------
1. Decide on Custom Program States

• REGISTER a map to record the pointer region that is allocated by kzalloc.  
 – Use: REGISTER_MAP_WITH_PROGRAMSTATE(AllocMap, const MemRegion*, bool)  
 – In our map (AllocMap), the key is the pointer’s MemRegion (specifically for dst->thread.sve_state) and the value is a flag (set to true) to indicate it was correctly allocated by kzalloc.

------------------------------------------------------------
2. Choose and Implement Callback Functions

a) checkBind  
 • When a binding (assignment) occurs, examine the statement where a function call returns a pointer which is assigned to a field.  
 • Steps to implement:
  – In checkBind, inspect the Stmt where the left-hand side (LHS) is used to store the call’s result.
  – Use the utility function ExprHasName on the LHS expression to check if it contains the name “sve_state”.  
  – Then, check if the right-hand side (RHS) is a call to kzalloc (by comparing the callee’s name; you can use Call.getCalleeIdentifier() from the CallEvent if available or use AST matching).
  – If both conditions are met, retrieve the MemRegion of the LHS (using getMemRegionFromExpr) and update AllocMap to record that this region was allocated from kzalloc.

b) checkBranchCondition  
 • Intercept branch condition statements using this callback.  
 • Steps to implement:
  – Analyze the condition (for example, an if-statement that performs a NULL check).
  – Use ExprHasName on the condition expression to check if it mistakenly refers to “za_state” (the wrong pointer) instead of “sve_state”.
  – If the condition text contains “za_state” while your program state map (AllocMap) holds a region for a kzalloc result (i.e. from “sve_state”), then you have detected the bug pattern.
  – Generate a bug report (using std::make_unique<BasicBugReport> or std::make_unique<PathSensitiveBugReport>) with a short message like “NULL check on wrong pointer: expected to check sve_state allocated by kzalloc.”

------------------------------------------------------------
3. Summary

• In checkBind, record any assignment where dst->thread.sve_state receives a kzalloc call by matching the text “sve_state”.  
• In checkBranchCondition, look for null-check conditions containing “za_state”.  
• If a branch condition checks “za_state” and you have already recorded an allocation for “sve_state”, then you should report a bug since the allocated pointer is being ignored.

This concise approach uses two callbacks and a simple program state map to track the algebraic relation between the allocation and the wrong NULL check. Follow these concrete steps, and you’ll have an effective checker for this pattern.