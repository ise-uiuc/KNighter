Your goal is to detect when a function is called with a null argument for a parameter that is declared “nonnull” either via an attribute or because it is a reference. You also want to make the whole analysis more precise by assuming that nonnull parameters really are nonnull at function entry. Here’s a concrete, step‐by‐step plan for how the checker works:

------------------------------------------------------------
Your plan here

1. REGISTER BUG TYPES  
   • The checker defines two bug types:  
     – BTAttrNonNull: reports “Argument with 'nonnull' attribute passed null”  
     – BTNullRefArg: reports “Dereference of null pointer” (when a reference turns out to be null)  
   • These bug types are used for reporting issues once a violation is detected.

2. PERFORM CHECKS BEFORE A FUNCTION CALL (checkPreCall)  
   • When a call is about to happen, obtain the underlying declaration (FD) of the function being called.  
   • Use utility functions that combine two sources of nonnull information:  
     – Function attributes (via specific nonnull attribute on the function)  
     – Parameter attributes (when the parameter itself is tagged with [[gnu::nonnull]])  
   • Produce a bitmask (SmallBitVector) indicating which parameters are expected to be nonnull.  
   • For each argument in the call that is marked nonnull (or is a reference type, because a reference must refer to a valid object):  
     – Retrieve the argument’s SVal and convert it to a DefinedSVal.  
     – If the SVal is not a valid location (or if it is deduced to be null by the constraint manager), then:  
         ▪ Try to generate an error node using generateErrorNode (or generateSink to catch a potential null dereference)  
         ▪ Based on whether the parameter’s nonnull expectation comes from an attribute or is a reference, call one of two report-generation helpers:  
             · genReportNullAttrNonNull (for nonnull attributes)  
             · genReportReferenceToNullPointer (for reference arguments)  
         ▪ Emit the bug report and highlight the source range of the problematic argument.  
   • Finally, update the program state to assume that parameters passing the check are nonnull, thus reducing false positives later in the analysis.

3. ASSUME NONNULL PARAMETERS AT FUNCTION BEGIN (checkBeginFunction)  
   • When entering a top-level function, retrieve the function’s declaration using the current LocationContext.  
   • Form an AnyCall object to gather parameter information uniformly.  
   • Determine which parameters have a nonnull attribute, again using the bitmask approach (getNonNullAttrs).  
   • For each parameter marked as nonnull (and that is of pointer type), obtain the location from the program state where the parameter is stored.  
   • Use the constraint manager to “assume” that the value of that parameter is nonnull.  
   • This assumption helps even if the null-dereference would occur later in the function body; the false positive rate is reduced by trusting the annotation.
    
4. UTILITY FUNCTIONS FOR ATTRIBUTE BITMASK CALCULATION  
   • The functions setBitsAccordingToFunctionAttributes and setBitsAccordingToParameterAttributes scan the function’s attributes and parameter declarations to build a bitmask (SmallBitVector) that marks parameters expected to be nonnull.  
   • Then, getNonNullAttrs is used to generate this bitmask and is invoked in both checkPreCall and checkBeginFunction.

5. REPORTING VIOLATIONS  
   • The two helper functions, genReportNullAttrNonNull and genReportReferenceToNullPointer, build and return a bug report (PathSensitiveBugReport) that includes an error message and highlights the source range where the issue occurs.  
   • When a null argument is detected in checkPreCall, one of these reports is emitted via C.emitReport.

6. REGISTERING THE CHECKER  
   • The final part of the checker registration hooks up the NonNullParamChecker with the CheckerManager so that it will be run during analysis.  
   • The functions registerNonNullParamChecker and shouldRegisterNonNullParamChecker are used for this purpose.

------------------------------------------------------------

By following these steps the checker examines every function call for null arguments passed to parameters that are required to be nonnull (either by attribute or by being a reference). It also sets up constraints at function entry so that subsequent analysis can safely assume these parameters cannot be null unless explicitly passed as such. This step-by-step plan gives you a clear and concrete path to implement or modify the checker in a minimal and precise way.