Your plan for the BitwiseShiftChecker can be summarized in these simple, concrete steps:

1. Intercept Shift Operators:  
   • Register a pre-statement callback for BinaryOperator nodes using checkPreStmt.  
   • In the callback, only process nodes where the operator is a left shift (<<) or right shift (>>).

2. Create a Validator Instance:  
   • For each shift operator node, instantiate a BitwiseShiftValidator (passing the BinaryOperator node, the CheckerContext, a BugType object, and the Pedantic flag).  
   • This helper class will encapsulate all the checks related to the shift operator.

3. Check for Overshift:  
   • In the validator’s run() method, first check that the right operand is less than the bit width of the left operand.  
   • Retrieve the left operand type and its bit width (using the ASTContext).  
   • Use an assumption helper (assumeRequirement) to check that “right operand < left_bit_width”.  
   • If the assumption fails, generate a bug report indicating that shifting by a value equal or larger than the bit-width is undefined.

4. Check Operand Negativity:  
   • Always check the right operand to ensure it is not negative: call assumeRequirement with the condition “right operand >= 0”.  
   • If Pedantic mode is enabled, also check the left operand (for << and >>) to ensure it is non-negative using the same mechanism.  
   • If any operand is found to be negative, produce an error report that details which operand is invalid for the shift.

5. (Pedantic Mode) Check for Left Shift Overflow:  
   • When doing a left shift on a signed type in pedantic mode, further verify that the shift does not cause overflow.  
   • Compute the maximum allowed shift based on the left operand’s width minus the bits already used (and possibly preserving the sign bit in C mode).  
   • Again, compare the right operand against this computed maximal allowed shift.  
   • If the right operand is too large, generate a bug report indicating that the left shift overflows the capacity of the type.

6. Update the State with Assumptions:  
   • If all checks pass, update the program state with any newly assumed conditions (using note tags) that reflect the non-negativity or bounds of the shift operands.  
   • This note is added to the transition so that later parts of the analysis know about these facts.

By following these concrete steps—intercepting only the relevant shift operators, verifying that the right operand respects both type width and non-negativity, and (if in pedantic mode) checking the left operand and left shift overflow, then finally summarizing the assumptions—you can build a correct and efficient BitwiseShiftChecker.