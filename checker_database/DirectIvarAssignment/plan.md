Your plan here

1. Build a mapping between properties and their backing ivars:
   • Create a DenseMap that associates every property (retrieved from the class interface’s list of instance properties) to its backing ivar.
   • For each property, try to resolve its backing ivar by first checking the property’s synthesized ivar, then by looking up an ivar with the default name (e.g. “_PropName”) and finally the property’s identifier.

2. Iterate over all methods in the Objective-C implementation:
   • Retrieve every instance method declared in the implementation.
   • Skip methods that are allowed to perform direct ivar assignment (e.g. methods belonging to families like “init”, “dealloc”, “copy”, “mutableCopy”, or methods whose selector contains “init”). (This filtering is done via a function pointer that you can override if needed.)
   • Also, bypass methods that are synthesized accessor stubs or use a specific annotation (like “objc_no_direct_instance_variable_assignment” to disable checking).

3. For each method that should be checked, traverse its statement AST tree:
   • Use a visitor (here, a custom AST walker called MethodCrawler) that visits every statement within the method body.
   • Focus on BinaryOperator nodes that represent assignment operations.

4. Check assignments that target an instance variable:
   • For each BinaryOperator, determine if it is an assignment.
   • Verify if the left-hand side of the assignment is an instance ivar reference (ObjCIvarRefExpr).
   • If it is, check whether the ivar is found in the previously built mapping.

5. Apply additional filters before reporting a violation:
   • Skip reporting if the ivar or its associated property is annotated with “objc_allow_direct_instance_variable_assignment”.
   • Also, ignore if the current method is the setter method (or getter method) for that property. This avoids false positives in the property’s own accessor methods.

6. Report a diagnostic:
   • Once you detect an invalid direct ivar assignment (i.e. the assignment is in a non-allowed method and not suppressed by annotation), create an error report.
   • Use the BugReporter API to emit a basic report with a message explaining that the assignment bypasses the property’s setter, advising the use of the setter instead.
   • Provide source location information (such as the ivar reference’s location) so that the user can easily pinpoint the problematic assignment.

Following these steps gives you a clear and concrete path toward implementing a simple and correct checker that flags direct assignments to ivars that back properties, except in allowed contexts.