Your plan here

1. Customize Program State:
   • Register a mapping to record a kzalloc allocation for a structure field. For example, use
     REGISTER_MAP_WITH_PROGRAMSTATE(AllocMap, const MemRegion*, std::string)
     where for each allocation made by kzalloc you map the memory region (that is, the destination of the assignment) to the name of the field that received the allocation (e.g. "sve_state").

2. Use checkPostCall to Record kzalloc Allocations:
   • In checkPostCall, intercept function calls.
   • If the callee’s name is "kzalloc", then use AST traversal (e.g. findSpecificTypeInParents) to obtain the LHS of the assignment. Ensure that the LHS is a MemberExpr.
   • Use ExprHasName (or extract the source text) on the MemberExpr target to check its field name.
   • If the field name is "sve_state", then obtain its MemRegion via getMemRegionFromExpr.
   • Record in AllocMap an entry mapping this MemRegion to the string "sve_state". This marks that a kzalloc allocation has taken place for the “sve_state” field.

3. Use checkBranchCondition to Detect an Incorrect NULL Check:
   • In checkBranchCondition, examine the condition expression of if-statements.
   • If the condition is a NULL check (for example a unary “!” operator applied to a pointer) and involves a MemberExpr, extract that MemberExpr using findSpecificTypeInChildren.
   • Use ExprHasName (or inspect the source text) on this MemberExpr. If the accessed field name is "za_state", then it is suspect.
   • Obtain the MemRegion for this pointer expression using getMemRegionFromExpr.
   • Look up this region (or, if necessary, compare their parent objects) in AllocMap. If you find that for the same base object there exists a recorded allocation on the "sve_state" field, then the code is mistakenly checking "za_state" instead of the allocated "sve_state".
   • In that case, emit a bug report (using generateNonFatalErrorNode and a short message such as "NULL check on wrong pointer") via the appropriate reporting mechanism.

4. (Optional) Use checkBind for Pointer Aliasing:
   • If necessary, track pointer aliasing by also registering a mapping via REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
   • Use checkBind to capture assignments of pointers (for instance, when one field is assigned to another). When an alias is detected, update PtrAliasMap so that when one pointer is marked as correct (or checked) the aliases are similarly updated.
   • In the current checker this step is optional but might improve accuracy if the NULL check is performed on an alias of dst->thread.za_state.

By following these steps—recording the kdalloc allocation with its intended field name in checkPostCall and then verifying in checkBranchCondition that the NULL check is applied to the correct field—you will detect cases where the wrong pointer field is NULL-checked. This is the simplest, yet concrete, approach to flag the bug pattern in question.