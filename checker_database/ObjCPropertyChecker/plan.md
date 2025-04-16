Your plan should follow these concrete steps:

------------------------------------------------------------
Your plan here

1. Identify the Target Declaration:
   • The checker is registered on AST declarations for Objective‑C properties. In the callback 
     checkASTDecl(), the checker receives an ObjCPropertyDecl (i.e. the property declaration).

2. Filter Out Inapplicable Properties:
   • Inside checkCopyMutable(), first ignore any property that is either read‑only or whose 
     setter method kind is not “copy.” This is because the issue only arises for properties 
     that are writable using the copy semantic.
   • Also, verify that the property’s type is an Objective‑C object pointer type. If it isn’t, 
     then there is nothing to check.

3. Check the Property’s Type for Mutability:
   • Retrieve the canonical type of the property (by calling getPointeeType() on the property’s 
     type) and convert it to a string.
   • Use a simple string check to see if the type name starts with "NSMutable". If it does not, 
     exit the checker because the property is not mutable.

4. Verify the Implementation Context:
   • Obtain the implementation declaration (ObjCImplDecl) associated with the property's interface:
     - If the declaration context is an ObjCInterfaceDecl, get the implementation from it.
     - If it is an ObjCCategoryDecl, obtain the class interface then its implementation.
   • Make sure that an implementation exists and that the user has NOT explicitly declared a setter 
     method for this property. The checker only reports issues for synthesized setters.

5. Report the Bug:
   • Construct an error message that indicates that a property of a mutable type with the “copy” 
     attribute is problematic because copying produces an immutable object.
   • Use the BugReporter (BR.EmitBasicReport()) to emit a basic report with the property’s source range 
     and location.
   • Use concrete diagnostic text that explains that storing an immutable object in a mutable property 
     is likely a logic error.

------------------------------------------------------------

By following these steps, you ensure that your checker only flags properties that are synthesized 
(with an implicitly generated setter) and have a mutable type marked with a “copy” attribute. 

This plan uses as few steps as possible while being concrete and clear at every decision point to 
help you write a correct and minimal checker.