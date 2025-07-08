```
1. Customize Program States:
   • REGISTER_MAP_WITH_PROGRAMSTATE(ResetDataFreeMap, const MemRegion*, bool)
     – This map tracks if a given reset_data region has already been freed.
   • REGISTER_MAP_WITH_PROGRAMSTATE(ResetDataCompletionCheckedMap, const MemRegion*, bool)
     – This map tracks if a call to completion_done() has been observed for the reset_data’s "compl" field.

2. Choose Callback Functions:
   A. checkBranchCondition:
      – When an if-condition is visited, use this callback to detect a condition that calls completion_done().
      – Use the utility function ExprHasName() on the condition expression text, looking for "completion_done".
      – If found, locate the argument passed to completion_done (e.g., via findSpecificTypeInChildren(CallExpr) or by parsing the subexpressions) and then call getMemRegionFromExpr() to get the reset_data region.
      – Update ResetDataCompletionCheckedMap for this region to true. This marks that the pointer has been checked before free.

   B. checkPostCall:
      – In checkPostCall, intercept calls to kfree.
      – When a kfree call is detected, extract its first argument by using getMemRegionFromExpr to obtain the MemRegion corresponding to reset_data.
      – Use checkBind (see next step) and program states to ensure the pointer being freed is the one we are tracking.
      – Look up the region in ResetDataFreeMap:
           ∗ If the region is not yet marked as freed, mark it as freed.
           ∗ If it is already marked as freed, then report a bug (using a short message like "Race condition: reset_data may be freed twice").
      – Additionally, check the ResetDataCompletionCheckedMap for that region:
           ∗ If the region is being freed but has not been verified via completion_done (i.e. not marked true), then report a bug indicating a potential race because the address was freed without the proper synchronization check.

   C. checkBind:
      – Use checkBind to track aliasing of reset_data pointers.
      – When a pointer is bound (for instance reset_data is assigned to another variable), update a PtrAliasMap (if needed) so that later a completion_done or kfree call over any alias can be correctly associated with the original reset_data region.
      – This ensures that if the alias’s region is used in a condition via completion_done or later freed, the same program state maps are updated accordingly.

3. Implementation Outline:
   • In checkBranchCondition, examine the source text of the condition for "completion_done". If found, extract the completion argument (likely reset_data->compl) and resolve its base reset_data region. Mark this region as having been checked.
   • In checkPostCall, for each call to kfree (identified by comparing the callee name), extract the pointer argument (reset_data) and:
         - Compare against ResetDataFreeMap: if already freed, report a duplicate free bug.
         - Otherwise, mark the region as freed.
         - Then look up the same region in ResetDataCompletionCheckedMap; if not marked, report a potential race condition.
   • In checkBind, propagate aliasing information so that a later free or completion check on any alias is correctly associated with the same reset_data region.

4. Bug Reporting:
   • Use std::make_unique<PathSensitiveBugReport> or std::make_unique<BasicBugReport> with a short message (e.g., "Race condition: reset_data freed without checking completion_done") to report the bug when detected.

By following these steps – customizing the program state to track both freeing and completion checks, then intercepting branch conditions (checkBranchCondition) and kfree calls (checkPostCall) while propagating pointer aliasing (checkBind) – you can write a checker that detects this race condition bug in the QAT driver.
```