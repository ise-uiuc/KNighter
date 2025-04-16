Your plan could be broken down into the following simple, concrete steps:

--------------------------------------------------
Your plan here

Step 1. Identify Target Ivars
• In the implementation’s AST declaration callback, the checker first finds the class interface (ObjCInterfaceDecl).
• Walk through each ivar in the interface.
• For each ivar, filter out those that are not private or have attributes that indicate they are to be ignored (for example, if they are marked with UnusedAttr, IBOutletAttr, IBOutletCollectionAttr, or are unnamed bitfields).
• For any ivar that passes these checks, add an entry in a DenseMap (IvarUsageMap) with the initial state set to Unused.

Step 2. Scan the Implementation Body
• Visit all methods of the class and scan their bodies for ivar references.
• Also scan related property implementations and category implementations.
• The scanning function works by traversing the Stmts recursively.
• On finding an ObjCIvarRefExpr (object ivar reference) that refers to an ivar already in the IvarUsageMap, update that ivar’s state to Used.
• For blocks or pseudo-objects that might indirectly reference ivars, scan their subexpressions to catch any ivar usages.

Step 3. Perform a Secondary Scan Over the Entire Translation Unit
• If any ivars in the IvarUsageMap remain marked as Unused after scanning the implementation, perform an additional scan of the entire translation unit.
• This scan covers function declarations within the implementation’s DeclContext.
• In this way, even if some ivar is used outside typical method bodies (for example in helper C functions), its state is updated to Used if found.

Step 4. Emit a Warning for Unused Ivars
• After all scanning steps, iterate over the IvarUsageMap.
• For each ivar still marked as Unused, create a bug report.
• The report describes that the instance variable is never accessed in the implementation.
• Finally, use the BugReporter (with a specific message and location) to emit the warning.

--------------------------------------------------
Each step is concrete and simple:
• Step 1 collects candidate ivars.
• Step 2 and 3 scan code for ivar usage.
• Step 4 reports any ivars that remain unused.

This plan minimizes the number of steps while ensuring each distinct part of the logic is implemented—a clear workflow for writing a correct checker to detect unused instance variables in Objective‑C classes.