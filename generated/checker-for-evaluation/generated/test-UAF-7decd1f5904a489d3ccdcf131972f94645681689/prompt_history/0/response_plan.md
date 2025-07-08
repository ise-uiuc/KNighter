Your plan is as follows:

--------------------------------------------------
1. Register a Program State Map:
   • Define a map (e.g., FreedSubflowMap) using
     REGISTER_MAP_WITH_PROGRAMSTATE(FreedSubflowMap, const MemRegion*, bool)
     to record each subflow object’s memory region and mark it as “freed” when mptcp_close_ssk is called.
   • Optionally, register a PtrAliasMap for alias tracking if you expect pointer aliasing between different variables.

2. Instrument the Call to mptcp_close_ssk in checkPostCall:
   • In your checkPostCall callback, intercept calls and check if the callee is "mptcp_close_ssk" (by comparing the function name).
   • Retrieve the subflow argument (the subflow pointer being freed) from the call event.
   • Use the utility function getMemRegionFromExpr on the subflow argument to obtain its memory region.
   • Update the FreedSubflowMap in the program state to mark this region with “true” (indicating it has been freed).
   • (If using PtrAliasMap, record any alias relationships so that if one pointer is freed, its aliases are also known to be freed.)

3. Detect Use-After-Free in checkLocation:
   • In your checkLocation callback (called on memory loads), intercept every load access.
   • For each memory access, use the utility function ExprHasName (with target string "request_join") on the expression that accesses the field. This helps identify when code is reading the field “request_join.”
   • If the check succeeds, retrieve the base memory region—for example, by examining the pointer expression that is used to access "request_join" (again, using getMemRegionFromExpr).
   • Consult the FreedSubflowMap. If the region is marked as freed, then you’ve detected a use-after-free.
   • Report the bug by generating a PathSensitiveBugReport (or BasicBugReport) with a short, clear message such as “UAF: Accessing field of freed subflow.”

4. (Optional) Track Pointer Aliasing with checkBind:
   • In checkBind, when a subflow pointer is assigned to another variable, record this aliasing relationship in the PtrAliasMap.
   • When marking a region as freed in checkPostCall, propagate the “freed” flag to all aliases so that any later access via these pointers in checkLocation is flagged.

--------------------------------------------------

This concise plan uses minimal callbacks:
• checkPostCall to mark subflow objects as freed when mptcp_close_ssk is invoked;
• checkLocation to detect field accesses (using the “request_join” name) after the object is freed.
This approach leverages the provided utility functions and minimizes complexity.