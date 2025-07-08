Your plan is as follows:

--------------------------------------------------
1. Decide on Custom Program States:
   • REGISTER a map (e.g. AllocationMap) to record allocations from kzalloc that are assigned to the expected pointer. Use:
     REGISTER_MAP_WITH_PROGRAMSTATE(AllocationMap, const MemRegion*, bool)
     This map will record that a memory region allocated via kzalloc was bound to the pointer “sve_state”. (No PtrAliasMap is needed in this case.)

--------------------------------------------------
2. Choose Callbacks and their Implementation Details:

   A. Tracking the Allocation via checkBind:
      • Use checkBind to intercept assignments.
      • In checkBind, inspect the statement (S) to see if it corresponds to a member assignment where the left-hand side is a MemberExpr.
      • If the MemberExpr’s field name equals "sve_state" and the right-hand side expression is the result of a kzalloc() call, then:
           - Retrieve the MemRegion corresponding to the left-hand side.
           - Record this region in AllocationMap (set the bool flag to true) meaning that a valid allocation to “sve_state” has occurred.
      • This ensures that we know when the allocation proper was made.

   B. Detecting the Incorrect Null Check via checkBranchCondition:
      • Hook into checkBranchCondition to examine each if-condition.
      • In checkBranchCondition, extract the source text of the condition using the provided utility, such as ExprHasName.
      • If the expression text contains “za_state” (the pointer that is unexpectedly checked instead of “sve_state”), then:
           - Look up in AllocationMap whether there is a corresponding allocation that was made for “sve_state”.
           - If such an allocation exists and the null-check is being performed on “za_state” rather than “sve_state”, report a bug.
      • Emit a bug report with a short message (for example, “NULL check on wrong pointer”) using e.g. std::make_unique<BasicBugReport>.

--------------------------------------------------
3. Reporting the Bug:
   • In checkBranchCondition, once you decide that the branch condition is incorrectly checking “za_state” after a kzalloc() assignment to “sve_state”:
       - Create an error node (non-fatal) by calling generateNonFatalErrorNode.
       - Emit the bug report with the short clear message.
       
--------------------------------------------------
Summary:
   • Use checkBind to capture when memory from kzalloc is bound to dst->thread.sve_state.
   • Use checkBranchCondition to detect when a NULL check is performed on dst->thread.za_state.
   • Use the custom AllocationMap to correlate the allocation with the later wrong null-check.
   • When the condition is detected, report with a concise message that the null check is being performed on the wrong pointer.
 
Follow these steps exactly and use the provided utility functions (such as ExprHasName) to simplify detection of the target member names in both binding and branch condition contexts. This simple, two-step approach minimizes additional complexity while clearly reporting the bug pattern.