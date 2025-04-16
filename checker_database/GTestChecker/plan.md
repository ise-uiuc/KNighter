Your goal is to make the analyzer “see through” the un-inlined gtest API constructors so that the boolean value (dictating assertion success) is properly propagated. Here’s a simple, step‐by‐step plan with concrete steps:

----------------------------------------------------------------------
Plan

1. Check for a post-call event and early exit if the constructor was inlined:
   • In the checkPostCall callback, first verify that the call did not get inlined (using C.wasInlined).
   • Then, cast the CallEvent to a CXXConstructorCall to gain access to constructor details.

2. Initialize that you’re looking at a gtest AssertionResult:
   • In the checkPostCall callback, first call a helper method (initIdentifierInfo) that initializes two IdentifierInfo pointers for “AssertionResult” (the class) and “success_” (the field).
   • Verify that the constructor’s parent record (its class) has the identifier “AssertionResult.” If not, exit.

3. Determine which constructor is being modeled:
   • If it is a copy constructor (has only one parameter and is a copy constructor), then forward to the copy-constructor model (modelAssertionResultCopyConstructor).
   • Otherwise, if it has one or two parameters and the first parameter’s type is a boolean or a reference to a boolean, then call the bool-constructor model (modelAssertionResultBoolConstructor).

4. Model the bool constructor:
   • In modelAssertionResultBoolConstructor, obtain the passed-in boolean argument.
     – If the argument is passed by reference, load from the referenced location.
   • Retrieve the “this” object from the constructor call.
   • Call getAssertionResultSuccessFieldValue to retrieve the SVal stored in the “success_” field of the new instance.
   • Use assumeValuesEqual to constrain the state to assume that the “success_” field is equal to the passed boolean value.
   • Add the resulting state transition.

5. Model the copy constructor:
   • In modelAssertionResultCopyConstructor, retrieve the source instance (the argument) and the target (this) instance.
   • Use getAssertionResultSuccessFieldValue to obtain each instance’s “success_” field value.
   • Call assumeValuesEqual to bind these two values in the program state and add the state transition.

6. Implement helper functions concretely:
   • initIdentifierInfo: Make sure to get IdentifierInfo for “AssertionResult” and “success_” from the AST context.
   • getAssertionResultSuccessFieldValue: Lookup the “success_” field in the AssertionResult record and extract its value from the given instance (using the program state’s LValue).
   • assumeValuesEqual: Create an equality constraint on the two SVal values with the analyzer’s constraint manager so that subsequent analysis will treat them as equal.

Following these steps will ensure that the gtest AssertionResult’s boolean value is propagated correctly (even when its constructors are not inlined), thus preventing false positives when user code calls gtest assertions.

----------------------------------------------------------------------

Each step is formulated to be as concrete and simple as possible. You only need to plug these steps into your checker’s implementation in the checkPostCall callback (and the various helper functions) to correctly model the behavior of the gtest AssertionResult.