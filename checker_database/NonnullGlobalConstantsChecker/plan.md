Your plan can be broken down into a few concrete steps:

------------------------------------------------------------
Step 1. Initialize the Required Identifier Information

• In the checkLocation callback, start by lazily initializing the identifiers for NSString, CFStringRef, CFBooleanRef, and CFNullRef.  
• Use a helper (initIdentifierInfo) that calls the AST context’s identifier table (via Ctx.Idents.get) to fill in the mutable data members.  
• This will allow later steps to recognize types associated with non-null globals.

------------------------------------------------------------
Step 2. Determine Whether a Location Refers to a Global Constant String

• In checkLocation, first check that the SVal is valid and that the event is a memory load.  
• Call the helper isGlobalConstString with your SVal.  
   – Inside isGlobalConstString, try to extract the MemRegionVal from the SVal.  
   – Verify that the region is actually a VarRegion attached to a VarDecl.  
   – Check that the variable has global storage and that its type is const‐qualified.  
   – Walk through any typedef or attributed type wrappers: if any intermediate type is marked as non‐null or if the final type is one of the recognized types (like char* const or typedefs matching CFStringRef, CFBooleanRef, or CFNullRef), then return true.  
• If it isn’t a matching constant global, simply return.

------------------------------------------------------------
Step 3. Enforce the Non-Null Assumption

• When isGlobalConstString returns true, get the SVal from the state for that location (V).  
• Convert the SVal into a DefinedOrUnknownSVal, which represents a concrete value that can be assumed to be non-null.  
• Use the state’s assume method (State->assume) with the condition true to add an assumption that the value is non-null.  
• Add a state transition based on this updated assumption.  
   – This effectively forces downstream analysis to treat these globals as non-null, eliminating unnecessary warnings or state paths.

------------------------------------------------------------
Step 4. Finalize the Checker

• The checker registers itself via a registration function that adds it to the analyzer.  
• The checkLocation handler runs at the memory location access point, applying the above logic.

------------------------------------------------------------
With these steps, the checker “NonnullGlobalConstantsChecker” assumes that certain global constant strings (and similar types) are non-null – using the type information, const qualifiers, and typedef links – then updating the program state accordingly. This simple but targeted approach improves the precision of analysis for frameworks that use these global constants.

This concrete step-by-step plan should allow you to write the checker correctly and straightforwardly.