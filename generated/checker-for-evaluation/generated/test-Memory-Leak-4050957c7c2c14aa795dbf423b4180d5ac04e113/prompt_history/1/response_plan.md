Your plan here

1. No additional program state customization is required.

2. Callback Choice: Use the checkASTCodeBody callback to analyze the function’s AST once it is fully parsed.

3. Implementation Steps:

   a. In checkASTCodeBody, first filter the FunctionDecl for the target function name (e.g. "gsc_runtime_resume"). You can do this by calling D->getNameAsString() and comparing it with the expected name.

   b. Once inside the target function, traverse the function body’s AST to locate an if statement that handles the error path. Focus on the then-body of the if statement, where the error cleanup happens.

   c. Within the if statement’s then-body, look for a while loop. Use a downward AST traversal (for instance, by using findSpecificTypeInChildren<WhileStmt>) to extract the while loop statement.

   d. Examine the while loop’s condition:
      - Verify that the condition is a binary operator with the ">" operator.
      - Confirm that the left-hand side of the binary operator is a unary operator representing pre-decrement (i.e. "--i").
      - Check that the right-hand side is the integer literal 0.
      This confirms the cleanup loop uses the condition (--i > 0).

   e. If the pattern is detected, report the bug:
      - Create a short, clear bug report message such as "Incorrect cleanup loop boundary" using std::make_unique<BasicBugReport> or PathSensitiveBugReport.
      - Emit the report using the provided Reporter mechanism.

4. By following these steps in the checkASTCodeBody callback, you efficiently detect and report the off-by-one error in the cleanup loop.

This plan leverages the simplest steps without extra complexity, while outlining concrete checks to identify the target pattern.