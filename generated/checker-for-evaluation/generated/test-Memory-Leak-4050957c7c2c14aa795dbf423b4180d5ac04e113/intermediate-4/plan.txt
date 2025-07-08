Your plan here

1. Decide on Program State Requirements:
   • No custom program state maps are necessary because the bug pattern is detected via syntactic conditions in the cleanup loop. We do not need to track value states or pointer aliasing.

2. Choose Callback Functions:
   • Use the checkBranchCondition() callback to inspect the condition of the while loop in the error cleanup block.
   • Optionally, use checkASTCodeBody() to ensure that the analysis is performed only inside functions of interest (e.g., “gsc_runtime_resume”).

3. Implementation Steps in checkBranchCondition:
   • When checkBranchCondition() is invoked, first determine if the condition originates from a while loop inside a function named “gsc_runtime_resume”. This can be done by using AST parent lookup utilities (e.g., using findSpecificTypeInParents()).
   • Examine the condition expression:
        - Check if it is a BinaryOperator with the operator ">".
        - Further inspect if the left-hand side is a UnaryOperator representing a pre-decrement (i.e., "--i").
        - Confirm that the right-hand side is the integer constant zero.
   • If these conditions are met, then the condition is of the form “while (--i > 0)” which corresponds to the off-by-one error pattern.

4. Reporting the Bug:
   • On detecting the pattern, call the bug reporting utility by creating a bug report (e.g., using std::make_unique<PathSensitiveBugReport>) with a short and clear message such as "Off-by-one error in cleanup loop".
   • Emit the report as a non-fatal error node.

5. Summary:
   • No complex program state modifications (like REGISTER_MAP_WITH_PROGRAMSTATE) are required.
   • Focus on analyzing the branch condition within the while loop, verify operator types and operands.
   • Restrict the check to the source function if possible to reduce false positives.
   • Report the bug as soon as the pattern “--i > 0” is identified.

This concise plan should allow you to write a checker that specifically catches the off-by-one error in the cleanup loop.