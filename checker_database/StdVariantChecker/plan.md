Your plan here

1. Register and Manage Program State Information
   • Define a program state map (VariantHeldTypeMap) that stores, for each std::variant instance (MemRegion), its currently held type (QualType). This lets the checker track what type is held in each variant object.

2. Intercept std::variant Construction and Assignment
   • In evalCall, detect calls that either construct or assign to a std::variant.
   • For constructor calls:
  – Check if the call is a std::variant constructor (or assignment operator) by matching a pre-defined CallDescription.
  – For a default constructor (with no arguments), record the first template parameter (the default held type) in VariantHeldTypeMap.
  – For one-argument constructors or assignment operators, use the helper (handleConstructorAndAssignment) to record the held type from the passed argument into VariantHeldTypeMap.
   
3. Intercept std::get Calls and Compare Types
   • Still in evalCall, detect std::get calls by matching the StdGet CallDescription.
   • In handleStdGetCall:
  – Ensure that the argument to std::get is an instance of std::variant.
  – Retrieve the MemRegion of the variant and look up its stored held type from VariantHeldTypeMap.
  – Extract the expected type from the template argument of std::get (which could be given as a type or index).
  – Compare the canonical form of the held type with the canonical form of the requested type.
  – If they do not match, generate a non-fatal bug report with a descriptive message showing the expected and retrieved types.

4. Clean Up Dead Variant Instances
   • Use the check::RegionChanges callback to detect when variant objects (or their associated regions) are invalidated.
   • Remove the corresponding entries from VariantHeldTypeMap for regions that are already dead.

By following these steps, the checker will monitor how std::variant objects are constructed, assignment-ed, and later accessed via std::get to ensure that the held type matches what is being retrieved, and it will report mismatches as errors.