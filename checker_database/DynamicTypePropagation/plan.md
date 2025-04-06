Your checker works by propagating dynamic type information and then comparing the tracked (inferred) types with the types expected by the program’s operations (casts, method calls, new expressions, etc.). Here is a step‐by‐step plan of how the checker detects type mismatches and other errors:

──────────────────────────────
Plan

1. Set Up Program State and Helper Maps
   • Register a program state map (MostSpecializedTypeArgsMap) that maps symbols to a pointer type (representing the most “informed” generic type known for that symbol). This map tracks type arguments for Objective‑C objects.
   • Create a BugType (and later initialize it in initBugType) to report generics type errors.

2. Propagate Fixed Types on Construction/Destruction (checkPreCall)
   • In checkPreCall, intercept C++ constructor and destructor calls.
   • Depending on the kind of construction (e.g. NonVirtualBase or VirtualBase), call recordFixedType to bind a fixed static type (from the class declaration) to the “this” object.
   • This ensures that during object construction the dynamic type can later be refined when more information is available.

3. Propagate Dynamic Type Information on Method Returns (checkPostCall)
   • In checkPostCall, for Objective‑C method calls:
  – If the message is sent to an alloc or new function, use inferReceiverType to deduce the type from the receiver and update the dynamic type info (setDynamicTypeInfo) of the returned region.
  – If it is an "init" call, propagate the dynamic type from the receiver to the return value.
   • For C++ new expressions (handled in checkPostStmt for CXXNewExpr), update the state with the newly allocated object’s type.

4. Refine Type Information Through Casts (checkPostStmt for CastExpr)
   • For cast expressions (ignoring explicit casts), call dynamicTypePropagationOnCasts.
   • Use getBetterObjCType to see if the cast provides a more precise type than the current dynamic type.
   • If so, update the dynamic type info in the program state—this means that the region’s stored type may be replaced with a more informative type.

5. Cleanup Dead Symbols (checkDeadSymbols)
   • Remove dead symbols from both the dynamic type map and the MostSpecializedTypeArgsMap.
   • This keeps the state clean and avoids propagating outdated type information.

6. Check Method Call Arguments for Generics Compliance (checkPreObjCMessage)
   • When a message is sent, retrieve the receiver’s symbol and see if it has an associated tracked type in MostSpecializedTypeArgsMap.
   • Look up the method declaration based on that tracked type (with findMethodDecl) and retrieve the method’s declared parameter types.
   • For each argument whose parameter type depends on a type parameter, substitute the type arguments (using substObjCTypeArgs) and then check if the passed argument’s type (possibly also tracked) is assignable to the parameter type.
   • If a mismatch is detected, call reportGenericsBug to generate an error message indicating a conversion incompatibility.

7. Propagate and Track Returned Types for Further Checks (checkPostObjCMessage)
   • In checkPostObjCMessage, handle special selectors like “class” and “superclass”:
  – For the “class” selector, infer the type of the class object and update the state.
   • For regular method calls, if the receiver’s tracked type is available, substitute type arguments into the method’s return type.
   • If the return type is specialized and not already tracked, add it to the state. This allows later calls using the returned value to benefit from refined type information.

8. Use Helper Functions to Compare and Refine Types
   • Functions like getMostInformativeDerivedClass (and its helpers) compare the current tracked type with a new candidate.
   • storeWhenMoreInformative will update the MostSpecializedTypeArgsMap only if the new type is “more specialized” (i.e. provides more type arguments) than the one already stored.
   • getBetterObjCType simply checks if a cast can yield a more precise dynamic type.

9. Report Errors when Inconsistencies Are Found
   • When the type inference (from casts or message argument checking) reveals an impossible conversion (i.e. the tracked type and the destination type are incompatible), call reportGenericsBug.
   • This function creates a diagnostic message that shows both the current tracked (inferred) type and the expected type, helping the programmer understand the source of the error.

──────────────────────────────
Summary

The overall detection plan is:

• Set up state tracking for dynamic types (via MostSpecializedTypeArgsMap) and initialize bug-reporting resources.
• Propagate type information from constructors, new expressions, and method calls.
• Refine the dynamic type during casts and compare it with the expected static types.
• When an Objective‑C message call is made, substitute actual type arguments into the method parameters and check whether the argument types conform.
• Report a bug if a type incompatibility is detected.

Each step refines the state so that later checks can catch errors (for example, if an object’s dynamic type does not match what its usage expects). This approach leverages program state transitions across various check callbacks (pre-call, post-call, post-statement, and dead-symbol cleanup) to track and update type information.