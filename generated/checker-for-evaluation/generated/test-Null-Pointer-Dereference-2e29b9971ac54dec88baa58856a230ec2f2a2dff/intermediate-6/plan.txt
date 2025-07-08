Your plan here

1. Customize Program State:
   • REGISTER a map (e.g., AllocatedFieldMap) using REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedFieldMap, const MemRegion*, std::string). This map will record the memory region returned by kzalloc along with the field name that is intended to be checked later (e.g., "sve_state").

2. Identify kzalloc Allocations (Using checkBind):
   • In the checkBind callback, detect assignments where the source (RHS) is a call to kzalloc.
   • Verify that the left-hand side (LHS) of the assignment is a MemberExpr. Use AST utilities to retrieve the field name.
   • If the field name matches the expected one (for example, "sve_state"), extract the destination’s MemRegion and record the pair (MemRegion, "sve_state") in the AllocatedFieldMap.
   • This step ensures that every successful kzalloc call is tracked along with the target member that should be later checked for nullness.

3. Detect Incorrect Null-Pointer Checks (Using checkBranchCondition):
   • In the checkBranchCondition callback, examine branch conditions that perform null checks.
   • Look for conditional expressions (e.g., BinaryOperator) where a MemberExpr is compared with null (or 0).
   • When a MemberExpr appears in such a null-check condition, extract its field name (using getNameAsString).
   • Use the AllocatedFieldMap (or try to locate the corresponding allocated region from earlier) to see if an earlier kzalloc call initialized a specific field (e.g., "sve_state") on the same base object.
   • If the field being tested in the condition does not match the field that was supposed to be tested (for example, testing "za_state" instead of "sve_state"), then trigger a bug report noting the incorrect null check.
   • The report should be short and clear, e.g., "NULL check on wrong variable after kzalloc".

4. Report the Bug:
   • Use a reporting facility (like std::make_unique<PathSensitiveBugReport> or std::make_unique<BasicBugReport>) to generate an error node.
   • Emit the bug report from the checkBranchCondition callback when the mismatch is detected.

By following these steps—tracking the allocation via checkBind and then verifying the appropriate null-check via checkBranchCondition—you can detect when the wrong field is being checked after a kzalloc call, matching the intended target patch pattern.