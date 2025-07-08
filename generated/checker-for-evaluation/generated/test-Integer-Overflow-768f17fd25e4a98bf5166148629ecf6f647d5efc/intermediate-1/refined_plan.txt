/*
1. Program State Customization:
   • No custom program state maps are necessary for this checker since the bug pattern only involves
     verifying the proper type casting in shift expressions. We'll work directly with the AST nodes.
     
2. Choose Callback Functions:
   • Use checkPreStmt to hook into BinaryOperator nodes because the bug pattern involves arithmetic
     left shifts (<<) where the left-hand side is not properly upcast to a 64-bit type.
     
3. Step-by-Step Implementation Plan:

   Step 1: Hook BinaryOperator Nodes
      - In the checkPreStmt callback, check if the statement is a BinaryOperator.
      - Verify that the operator is the left shift operator ("<<").

   Step 2: Analyze the Left-Hand Side (LHS) Expression
      - For the LHS expression of the BinaryOperator:
         • Determine its type. If the type is an integer type and its width is 32 bits,
           this is a candidate for potential overflow.
      - Use utility functions like getType() on the expression and check if it is casted to a 64-bit type.
      - Specifically, check if the LHS is a CastExpr casting to an unsigned 64-bit type (e.g., "u64").
         • If a CastExpr exists and the destination type is 64-bit, then the expression is safe.
         • Otherwise, the shift is conducted with a 32-bit operand.

   Step 3: Issue a Bug Report on Offending Shift Expressions
      - If the LHS is determined to be 32-bit (or not upcast to a 64-bit type) before shifting,
        then prepare a bug report.
      - Use a simple bug reporting mechanism like std::make_unique<BasicBugReport> to report a short
        and clear message such as "Potential integer overflow: left shift performed on a 32-bit value."
      - Emit the bug report to alert the user of the detected pattern.
      
   Step 4: Finalize and Review the Checker
      - Ensure the checker correctly identifies shift operations that do not include an explicit cast to u64.
      - Use the provided utility functions if needed for AST navigation (e.g., findSpecificTypeInChildren) to
        dig into the LHS expression to confirm whether a proper cast is present.
        
This plan provides a clear, concise approach to implementing a checker that detects arithmetic shift operations
performed on 32-bit values without an upcast to 64-bit, which matches the target bug pattern indicated by the patch.
*/