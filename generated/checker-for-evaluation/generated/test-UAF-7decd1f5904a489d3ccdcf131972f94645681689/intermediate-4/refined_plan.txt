Your plan is as follows:

1. Define Program State Maps:
   • Register a state map (e.g. FreeMap) to track memory regions that have been freed. Use
     REGISTER_MAP_WITH_PROGRAMSTATE(FreeMap, const MemRegion*, bool) where a value of true
     indicates that the region has been freed.
   • (Optional) Register a pointer alias map (PtrAliasMap) to track pointer aliases. This will
     help when a pointer is later used via an alias. Use:
        REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

2. Intercept the Freeing Call (checkPostCall):
   • In the checkPostCall callback, detect calls to the function mptcp_close_ssk.
   • When this function is called, extract the argument corresponding to the subflow that is
     being closed.
   • Retrieve the memory region of that subflow using getMemRegionFromExpr.
   • Mark this region in FreeMap as freed.
   • (Optionally) Update the PtrAliasMap in checkBind if you want to propagate this information
     to any other pointer that aliases the subflow.

3. Detect Use-After-Free Accesses (checkLocation):
   • In the checkLocation callback, react when a location is loaded. If the location SVal is being
     accessed (IsLoad == true), retrieve the underlying MemRegion using getMemRegionFromExpr.
   • Consult the FreeMap to see if the accessed region (or any of its aliases via PtrAliasMap) has
     been marked as freed.
   • If yes, generate a short warning (e.g. “UAF: field access on freed object”) using a bug
     report (for example, with std::make_unique<PathSensitiveBugReport>).

4. Track Pointer Aliasing (checkBind):
   • In the checkBind callback, update the PtrAliasMap so that when a pointer (or a member field of a
     freed object) is assigned to another pointer, the alias mapping is recorded.
   • This ensures that any later dereference, even through an alias, will consult the FreeMap via
     the PtrAliasMap.

By following these steps—customizing the program states, intercepting mptcp_close_ssk in checkPostCall to mark the subflow as freed, and checking all memory loads in checkLocation—you can reliably detect when code reads from a field (such as request_join) after the subflow was freed, thereby flagging the use-after-free issue.