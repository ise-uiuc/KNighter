Your plan is as follows:

------------------------------------------------------------
1. Customize Program State

• REGISTER a map in the program state (e.g. ResetDataMap) to record the “completion” status for each reset_data region.  
  – Use REGISTER_MAP_WITH_PROGRAMSTATE(ResetDataMap, const MemRegion*, bool)  
  – The bool value will be false by default (meaning “not completed”) and set to true once a call to completion_done() is detected on that structure.

Optionally, if you want to track pointer aliases (e.g. when reset_data is stored into another variable), register a pointer alias map (PtrAliasMap) using REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*).

------------------------------------------------------------
2. Choose Callback Functions

A. Intercepting Function Calls (checkPreCall):  
  i. Detect calls to completion_done():  
   – In the checkPreCall callback, if the callee’s name equals "completion_done", extract its argument (which is expected to be the address of the reset_data’s completion field).  
   – Use getMemRegionFromExpr() on the argument to get the MemRegion of the container (the reset_data)  
   – Update ResetDataMap for that region: mark it true to indicate that completion_done() has been called.  
    [This tells you that the caller may have already freed the structure.]

  ii. Detect calls to kfree (or similar free functions):  
   – In checkPreCall, when the callee’s name is "kfree", extract the pointer argument using getMemRegionFromExpr().  
   – Optionally use ExprHasName() to make sure the argument expression indicates it is a reset_data structure (e.g. by checking for "reset_data" if applicable).  
   – Look up the pointer’s associated region in ResetDataMap.  
   – If that region is already marked as true (completion_done was already invoked), then report a bug “Use-after-free: reset_data freed twice” (using generateNonFatalErrorNode and a concise bug message).  
   – This warns that the worker and the caller might both free the same allocation.

B. (Optionally) Pointer Aliasing (checkBind):  
  – In checkBind, whenever a reset_data pointer is stored into another variable, record this aliasing in PtrAliasMap.  
  – This step ensures that a NULL check or the completion_done status update later propagates to all aliases.
  – Then, when intercepting kfree calls as in Step A.ii, check not only the explicit reset_data region but also its aliases stored in PtrAliasMap.

------------------------------------------------------------
3. Flow Summary

• At allocation (not needed to intercept allocations in this pattern), reset_data is created.  
• When completion_done() is called, your checker marks the corresponding reset_data region as “completed” in ResetDataMap.  
• Later, if a free (kfree) call is intercepted on the same memory (by matching its MemRegion, taking into account any aliases), the checker sees that the region was already “completed” (i.e., freed via the caller side) and reports a potential use‐after‐free race condition.

------------------------------------------------------------
4. Implementation Guidelines

• In checkPreCall, efficiently extract the function name using Call.getCalleeIdentifier() and compare it with "completion_done" or "kfree".  
• Use the provided utility functions (getMemRegionFromExpr, ExprHasName) to obtain the memory region from the call’s argument.  
• Issue a concise bug report (e.g. “Race: reset_data freed twice”) using generateNonFatalErrorNode and a PathSensitiveBugReport.  
• Keep the implementation simple by directly mapping the observed call events to updates in the ResetDataMap.

------------------------------------------------------------
This plan gives you a clear, concrete set of steps with the necessary callbacks and program state management to detect the race condition with an improper ownership transfer of reset_data.