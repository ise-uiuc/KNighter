Your plan is as follows:

1. Customize Program States  
 • REGISTER a ProgramState map (e.g., REGISTER_MAP_WITH_PROGRAMSTATE(InitRegionMap, const MemRegion*, bool)) that maps memory regions (representing structure variables) to an “initialized” flag.  
 • REGISTER a PtrAliasMap using the same mechanism to track alias relationships for structure pointers. This helps propagate a “zeroed” state when a memset is detected.

2. Track Memory Initialization with memset (using checkPreCall)  
 • In checkPreCall, intercept calls to memset.  
 • Check that the callee’s name is “memset” and that the second argument evaluates to 0.  
 • Using getMemRegionFromExpr, extract the target memory region from the first argument.  
 • Update InitRegionMap to mark that region (and its tracked aliases in PtrAliasMap) as fully initialized.

3. Record Structure Bindings and Aliases (using checkBind)  
 • In checkBind, when a structure pointer is assigned to another pointer (e.g., a local variable alias), update the PtrAliasMap so that any “initialized” flag set for one region is available on its aliases.  
 • This guarantees that if one alias is zeroed, the checker treats all aliases as initialized.

4. Detect Uninitialized Structure Being Used in Data Copy (using checkPostCall)  
 • In checkPostCall, intercept calls to user-copying helper functions (e.g., nla_put, nla_put_u16, nla_put_64bit).  
 • For each such call, examine the argument that provides the pointer to the structure.  
 • Retrieve its underlying memory region via getMemRegionFromExpr.  
 • Query InitRegionMap (and follow aliases via PtrAliasMap) to check if this region was zeroed.  
 • If the region is not marked as “initialized”, then it indicates that a structure with implicit padding may be partially initialized. In that case, issue a short, clear bug report (using std::make_unique<PathSensitiveBugReport> or BasicBugReport) reporting potential kernel-infoleak.

5. Reporting  
 • Keep the report message short (e.g., “Structure not fully zeroed before user copy – potential information leak”).  
 • Generate a non-fatal error node and report the bug in checkPostCall.

This simple plan requires intercepting memset calls (to mark a structure as fully initialized) and user copy calls (to report when an uninitialized structure is used). Using ProgramState maps and alias propagation ensures that even when a structure is assigned to an alias, the checker’s knowledge is consistent.