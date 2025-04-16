Your plan for detecting missing super-calls with this checker is as follows:

------------------------------------------------------------
Your plan here

1. Initialization and Setup
   • During the AST visit of an Objective-C implementation declaration (ObjCImplementationDecl), first initialize the selector look-up table if it hasn’t been done already. This table (SelectorsForClass) maps superclass names (such as UIViewController, UIResponder, etc.) to sets of selectors (method names) that require a call to super.
   • Populate the table by calling fillSelectors for each known superclass and its list of mandatory selectors.

2. Identify Checkable Classes
   • In the checkASTDecl callback, for each ObjC implementation declaration, look upward along the inheritance chain.
   • Check if any superclass name appears in the selectors table. If so, treat the class as "checkable" and store the found superclass name.

3. Analyze Each Instance Method
   • Iterate over all instance methods in the implementation.
   • For each method, retrieve its selector.
   • Check whether the selector is one of the ones registered for the identified superclass (via SelectorsForClass[SuperclassName]). This determines if the method must call its super implementation.

4. Look for a Super-Call in the Method Body
   • If the method is checkable and has a body, traverse its AST using the FindSuperCallVisitor.
   • The visitor is constructed with the current method selector.
   • In the visitor, for every ObjCMessageExpr encountered:
       – Check whether the selector matches the method’s selector.
       – Check if the receiver kind is “super” (i.e., the message is sent to the superclass).
       – Mark a flag (DoesCallSuper) if a valid super call is found.
   • The visitor stops early if the flag becomes true.

5. Report a Diagnostic if a Super-Call Was Missed
   • After traversing the method body, if the flag DoesCallSuper is still false, then the method did not call the corresponding superclass method.
   • Use BugReporter to emit a diagnostic:
       – Create a PathDiagnosticLocation at the end of the method’s body.
       – Compose a descriptive message giving the missing [super selector] call, including relevant class and method names.
       – Emit the bug report.

------------------------------------------------------------
This step-by-step and concrete plan will guide you in writing the checker correctly by following each concrete step of setting up state, checking if a class is eligible for the check, inspecting each method, traversing its body for a super message call, and finally reporting a bug if the call is missing.