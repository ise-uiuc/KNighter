Your plan can be described in a few simple, concrete steps:

------------------------------------------------------------

Step 1. Filter Boolean Stores  
• When a value is bound (via checkBind), first extract the memory region from the location.  
• Use the region’s type information to determine if the target variable is a Boolean.  
• Only continue if isBooleanType returns true—this limits our check to assignments to Boolean variables.

------------------------------------------------------------

Step 2. Extract and Verify the Value  
• Retrieve the right-hand side (RHS) value of the assignment and make sure it is defined (an instance of NonLoc).  
• If the value isn’t defined (or isn’t a NonLoc), skip further checking because other checkers will handle that.

------------------------------------------------------------

Step 3. Constrain the Value Range  
• Use the ConstraintManager to check if the assigned value can be assumed to lie in the inclusive range [0, 1].  
   - This means call assumeInclusiveRangeDual to split the program state into two: one in which the value is in range (StIn) and one where it is not (StOut).  
• If the “in-range” state (StIn) is not possible, then the value must lie outside [0, 1].  
   - In that case, immediately report an error by calling the emitReport helper.

------------------------------------------------------------

Step 4. Check for Tainted Values  
• In addition to the range check, test whether the value is tainted using the appropriate Taint API (taint::isTainted).  
• If both an out-of-range condition and taint are detected, report this specially by passing a flag (IsTainted = true) to emitReport.

------------------------------------------------------------

Step 5. Emit a Report if Necessary  
• In the emitReport function, create a non-fatal error node to attach the bug report.  
• The Bug Report message is determined by whether the value is merely non-Boolean (message: “Assignment of a non-Boolean value”) or if it might be tainted (message: "Might assign a tainted non-Boolean value").  
• Finally, use C.emitReport to generate the bug report.

------------------------------------------------------------

This plan is simple and straightforward, using only the checkBind callback:  
1. Identify assignments to Boolean variables,  
2. Extract and examine the assigned value,  
3. Use the constraint manager to enforce that it must be 0 or 1, and  
4. Report if the value is out of range (and optionally if it’s tainted).

Following these steps should let you write a checker that detects assignments of non-Boolean values in a clear and concrete way.