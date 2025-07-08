Your plan here

1. Identify the Target Function:
   • In the checkASTCodeBody callback, inspect every function definition.
   • Filter for the function whose name is "thermal_zone_device_register_with_trips" (using getNameAsString() on the FunctionDecl).

2. Traverse the Function Body:
   • Once the target function is found, traverse its AST body to locate:
     - The memcpy() call that copies the trips array.
     - The assignment statement where the structure’s num_trips field is set.
   • You can use utility functions such as findSpecificTypeInChildren to search for CallExpr nodes and BinaryOperator or CXXOperatorCallExpr nodes representing assignments.

3. Record Statement Locations:
   • For each identified statement (the memcpy call and the num_trips assignment), record its source-location (using getBeginLoc()).
   • Use the SourceManager from CheckerContext to compare the positions.

4. Check the Order:
   • Compare the source locations: if the memcpy() call appears before the num_trips assignment, flag the potential bug.
   • Conversely, if num_trips is assigned before memcpy(), no bug is reported.
  
5. Report the Bug:
   • If the faulty ordering is detected, generate a bug report using std::make_unique<BasicBugReport> or PathSensitiveBugReport.
   • The report message should be short and clear (e.g., "num_trips assigned after memcpy causing fortify check failure").

6. (Optional) Program State:
   • For this checker, no custom program state maps (REGISTER_MAP_WITH_PROGRAMSTATE or PtrAliasMap) are needed because you are only comparing the ordering of two statements in the same function body.

7. Implementation Steps Summary:
   • In checkASTCodeBody, check if the FunctionDecl’s name equals "thermal_zone_device_register_with_trips".
   • Traverse its body to locate:
         a. memcpy() call – verify by checking if the callee’s name is "memcpy" (using ExprHasName).
         b. Assignment to num_trips – identify an assignment where the left-hand side’s member name is "num_trips".
   • Use the SourceManager to fetch the beginning location of these statements.
   • If the memcpy call is before the num_trips assignment, report the bug.
   • Emit a concise bug message indicating that the structure’s size field (num_trips) is set too late.

This plan provides a straightforward path using a single callback (checkASTCodeBody) and simple AST traversal with location comparisons to detect the detected bug pattern.