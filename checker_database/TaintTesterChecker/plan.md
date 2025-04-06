Your plan for the TaintTesterChecker is as follows:

1. When an expression finishes evaluating, the checkPostStmt callback is invoked with the expression (E) and the current CheckerContext (C).

2. Retrieve the current program state from the CheckerContext. This state tracks information such as which values are currently tainted.

3. Check if the expression E has become tainted by using the helper function isTainted. This function consults the program state (and possibly contextual data) to decide if E carries taint.

4. If isTainted returns true, create an ExplodedNode (a point in the analysis graph) for a non-fatal error. This marks the location where a potential taint issue is detected.

5. Construct a bug report with a descriptive message (in this case, simply "tainted") and attach the source range of the expression E to highlight where the problem is.

6. Finally, emit the bug report to inform users about the flawed use of tainted data.

This step-by-step plan is simple but covers all necessary actions: post-statement evaluation, state checking for taint, error node generation, bug report creation, and finally, reporting the taint issue.