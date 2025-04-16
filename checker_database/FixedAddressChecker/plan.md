Your goal is to detect when a fixed (hard‐coded) nonzero constant is used as an address in a pointer assignment. Here’s a simple, concrete plan:

----------------------------------------------------------------
Plan

1. Register a callback for assignment expressions:
   • Use the PreStmt callback for BinaryOperator.
   • This ensures that every assignment statement is inspected before evaluation.

2. Check if the binary operator is an assignment:
   • Verify that the operator (B->getOpcode()) is BO_Assign.
   • If not, simply return (do nothing).

3. Verify that the assignment involves a pointer:
   • Get the type of the left-hand side (B->getType()).
   • Check that this type is a pointer type.
   • If it isn’t, return immediately.

4. Evaluate the right-hand side (RHS) value:
   • Retrieve the SVal from the RHS by calling C.getSVal(B->getRHS()).
   • Check that this SVal is a constant.
         – This is important because only constant addresses are suspect.
   • Ensure that the constant is not zero.
         – A zero constant is typically used to represent NULL, and not a fixed address.

5. Report the bug if a fixed address is detected:
   • Generate a non-fatal error node using C.generateNonFatalErrorNode(); if it fails, exit.
   • Create a PathSensitiveBugReport with a message explaining that using a fixed address is nonportable.
   • Add the source range (of the RHS) to the bug report to help pinpoint the issue.
   • Emit the warning by calling C.emitReport() with the report.

6. (Registration) In the checker registration function:
   • Register the FixedAddressChecker with CheckerManager.
   • This makes sure that the checker is hooked into the analysis and will run for the targeted statements.

----------------------------------------------------------------

Each step is direct and simple. The checker first distinguishes assignment statements, then filters those that deal with pointer types. It then inspects the value being assigned to see if it is a constant non-zero value—if so, it complains that a fixed address is being used, which is not portable. This plan mirrors the structure of similar checkers while keeping the logic straightforward and minimal.

You can now implement the checker using these steps.