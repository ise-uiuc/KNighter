Below is a simple, concrete plan that describes how the MacOSXAPIChecker detects problems with dispatch_once-like calls:

--------------------------------------------------
Plan

1. Identify the API call to check:
   • Register a pre-statement callback for CallExpr.
   • In checkPreStmt(), get the callee’s name from the call expression.
   • Use an LLVM StringSwitch to see whether the function is one of: "dispatch_once", "_dispatch_once", or "dispatch_once_f".
   • If a matching name is found, select the CheckDispatchOnce subroutine.

2. Analyze the predicate argument:
   • In CheckDispatchOnce(), first check that the call has at least one argument.
   • Retrieve the first argument’s SVal and convert it into a MemRegion.
   • If no MemRegion is found, do nothing. (This means the parameter isn’t something you can analyze.)

3. Determine if the predicate comes from a proper allocation:
   • From the retrieved region, get its base region.
   • Then find the enclosing memory space via getMemorySpace().
   • If the base region ultimately lies in the GlobalsSpaceRegion (e.g. a global variable), then the use is allowed and no warning is needed.
   • Otherwise, the memory is transient (e.g. local stack or heap/local allocation).

4. Prepare and issue a diagnostic:
   • Use the function name (adjusted for macro expansion if needed) and the memory’s details to build a clear warning message.
   • For example, if the pointer comes from a local variable, mention that using local (non-static) data for the predicate in dispatch_once is potentially dangerous.
   • Optionally include a suggestion (for instance, “Perhaps you intended to declare the variable as 'static'?”).

5. Emit the error:
   • Generate an error node with generateErrorNode().
   • Create a PathSensitiveBugReport that includes the warning message.
   • Add the source range for the predicate argument so that the part of the source responsible gets highlighted.
   • Finally, use C.emitReport() to output the diagnostic.

--------------------------------------------------
This plan outlines each step in a straightforward way so that you can follow it and implement the checker correctly.