Your plan can be implemented in three concrete steps. We do not need to customize a program state for aliasing or pointer analysis because what we need is to inspect the AST for a specific ordering of statements inside the __flush_work() function. In this case, we want to ensure that the shared memory field (work->data) is read only after checking the controlling flag (from_cancel). Here is your plan:

--------------------------------------------------
1. Hook the AST code body of __flush_work() using checkASTCodeBody

• In checkASTCodeBody, examine every function definition.
• Filter for the function whose name is "__flush_work" (using D->getNameAsString()).
• Once inside __flush_work(), traverse its statement body.

--------------------------------------------------
2. Traverse the Function Body to Identify the Unguarded Read

• Look for an assignment statement that reads work->data. In the buggy code this takes the form:
  data = *work_data_bits(work);
• Use the utility function findSpecificTypeInChildren<CallExpr>(S) (or, more generally, walk the AST nodes) to detect a call to work_data_bits() whose result is immediately dereferenced.
• Determine if this read is performed unconditionally – that is, verify that it is not enclosed inside a conditional block whose condition tests the controlling flag (from_cancel). You can achieve this by using findSpecificTypeInParents<IfStmt>(stmt) to check if the read is inside an if statement and then examine the if condition (using getSourceText, or by checking for the occurrence of "from_cancel") to see if the branch condition is guarding the read.
• In our case, if the assignment is at the top level (or not nested in an if that first checks "from_cancel"), then it is an unguarded read.

--------------------------------------------------
3. Report the Bug

• If an unguarded read is detected, generate a warning.
• Create a bug report with a short message such as "Shared memory read unguarded by from_cancel check" using a basic bug report (for example, by calling std::make_unique<BasicBugReport>(...) or std::make_unique<PathSensitiveBugReport>(...)).
• Emit the bug report (using the CheckerContext’s reporting facilities).

--------------------------------------------------
By following these steps you will have a simple checker that inspects __flush_work(), verifies that the shared memory field is accessed only if from_cancel is true, and flags the pattern where work->data is read before the conditional check.

This plan uses only checkASTCodeBody (for function-level analysis) and then helper utilities (findSpecificTypeInChildren and findSpecificTypeInParents) to locate and analyze specific expressions in the AST. No extra program state mapping or alias tracking is necessary for this simple check.