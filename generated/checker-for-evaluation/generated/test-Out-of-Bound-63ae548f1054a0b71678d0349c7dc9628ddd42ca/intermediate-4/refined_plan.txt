/*
Your plan here

1. Customize Program State:
   • No custom program state maps are needed for this checker.

2. Choose Callback Functions:
   • Use checkASTCodeBody to restrict the check to the function “cm_helper_translate_curve_to_hw_format”.
   • Use checkPreStmt to inspect ForStmt nodes (loop constructs) within the function body.

3. Implementation Steps:
   a. In checkASTCodeBody, examine each function’s definition. If the function’s name is "cm_helper_translate_curve_to_hw_format", traverse its body.
   b. Within the function body, use the AST traversal utilities (or alternatively, use checkPreStmt) to locate ForStmt nodes that represent loop constructs.
   c. For each ForStmt encountered, search its children for ArraySubscriptExpr nodes that access the color channel arrays (for example, “output_tf->tf_pts.red”, “output_tf->tf_pts.green”, or “output_tf->tf_pts.blue”).
   d. In the same loop body, examine any IfStmt (using findSpecificTypeInChildren<IfStmt>) to determine whether there is a branch condition that involves the macro name "TRANSFER_FUNC_POINTS". Use the provided utility function ExprHasName() on the if-condition’s expression to look for the target string.
   e. If an ArraySubscriptExpr is found that uses an index variable (such as “i”) and no corresponding if-condition is detected that checks whether the index is less than TRANSFER_FUNC_POINTS, then conclude that the bug pattern is present.
   f. Report the bug by generating a short and clear bug report using std::make_unique<PathSensitiveBugReport> (or std::make_unique<BasicBugReport>), with a message like "Potential out-of-bounds array access: missing index bounds check".

4. Final Notes:
   • Keep the checker simple by only focusing on the function “cm_helper_translate_curve_to_hw_format” and its for loops.
   • Use the available utility functions (like ExprHasName and findSpecificTypeInChildren) to traverse and inspect the AST where needed.
   • No pointer aliasing or state maps are required because the issue is a missing bounds check in loop iteration logic.

This plan provides concrete and sequential guidance to implement the bug checker.
*/