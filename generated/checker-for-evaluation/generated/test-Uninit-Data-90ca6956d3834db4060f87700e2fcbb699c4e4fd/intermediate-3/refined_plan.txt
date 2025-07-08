Your plan should be as simple as possible while still precisely catching declarations of auto‐cleanup pointers that lack an initializer. Here’s a concrete step‐by‐step plan:

1. Decide on Program State Customization:
   • No need to register custom Program State or maps for this check because you are only inspecting the declaration itself. This checker looks at a single declaration to decide if its auto-cleanup pointer is initialized. 

2. Choose the Callback Function:
   • Use the callback function checkPostStmt for DeclStmt. This callback will examine every declaration statement to find pointer variable declarations.

3. Implement the Callback Function (checkPostStmt):
   • For each DeclStmt, iterate over all contained variable declarations (VarDecl).
   • For each VarDecl, first check if the variable’s type is a pointer type. This can be done by using getType() and testing whether it is a pointer (e.g., using isPointerType()).
   • Next, check if the variable is declared with automatic cleanup (the __free attribute). Depending on your AST attribute representation, this might be by inspecting a particular attribute (or checking if the source text includes “__free” using ExprHasName if needed).
   • Then check whether the variable declaration has an initializer. You can call hasInit() on the VarDecl.
   • If the variable is a pointer with __free cleanup and has NO initializer (or is not explicitly set to NULL), then record this case as a potential bug.

4. Report the Bug:
   • If you detect a variable matching the bug pattern, report it with a short and clear message (for example, “Auto-cleanup pointer not initialized to NULL”).
   • Create a bug report using std::make_unique<BasicBugReport> or std::make_unique<PathSensitiveBugReport> as appropriate. Emit the bug report within checkPostStmt.

5. (Optional) Consider Further Conditions:
   • If desired, further check if the initializer (if present) is a literal constant that is equivalent to NULL (e.g., 0 or NULL). If it is not, then report a bug.
   • You can leverage utility functions if you need to extract the source text (using ExprHasName) or evaluate the constant value, although that additional check is optional for catching the missing initialization.

By following these concrete steps—using checkPostStmt to inspect every variable declaration, verifying that pointer types with an auto-cleanup (__free) attribute are initialized (with a NULL initializer)—you can easily compose a checker that reports a bug when such pointers are not explicitly set to NULL.