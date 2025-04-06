Your plan can be summarized in five concrete steps. Each step explains exactly what the checker does and how it uses the program state to drive decisions:

------------------------------------------------------------
Step 1. Maintain Implication Maps

• Define two program state maps (using REGISTER_MAP_WITH_PROGRAMSTATE):
  – NonNullImplicationMap: Saves pairs (antecedent, consequent) to capture that “if the return value is nonnull then the argument is nonnull.”
  – NullImplicationMap: Saves pairs (antecedent, consequent) so that “if the argument is null then the return value is null.”

• These maps record relationships between symbols that act as “implications” for later assumptions.

------------------------------------------------------------
Step 2. Post-Call Analysis

• In the checkPostCall callback, first verify the call is from a system header.
  
• For function calls returning a pointer, if the return type is annotated _Nonnull (or determined nonnull via isNonNullPtr):
  – Retrieve the return location.
  – Immediately add an assumption (via State->assume) that the location is non-null.

• This step “trusts” the nonnull annotation by forcing the analyzer to treat the result as not null.

------------------------------------------------------------
Step 3. Post-ObjC Message Processing

• In the checkPostObjCMessage callback, check the receiver’s type and the message’s selector.

• For NSMutableDictionary setters (setObject:forKeyedSubscript or setObject:forKey):
  – Retrieve the second argument (the “index”) and assume it is nonnull because a nil key would throw an exception.

• For NSDictionary getters (objectForKeyedSubscript or objectForKey):
  – Obtain the key (argument) and the return value symbol.
  – Record two implications:
     o In NonNullImplicationMap, store (return value → key) to express “if the return is nonnull, its key must be nonnull.”
     o In NullImplicationMap, store (key → return value) to express “if the key is null then the result must be null.”

------------------------------------------------------------
Step 4. Propagating Assumptions via evalAssume

• In evalAssume, when the analyzer is evaluating a branch condition (with an assumed boolean value), retrieve the condition’s symbol.
  
• For each symbol contained in the condition (if its complexity is below an acceptable threshold):
  – Call addImplication to update the state with the implied assumption using the NonNull or Null maps.
  – Essentially, if the symbol is assumed true/false, then add the corresponding assumption about the related symbol.

• This step propagates the “trusted” nonnull relationships into further assumptions.

------------------------------------------------------------
Step 5. Cleaning Up Dead Symbols

• In checkDeadSymbols, iterate through both implication maps.
  
• Remove any mapping that contains a dead symbol (one that is no longer live in the current program state).

• This cleanup avoids carrying stale implications and keeps the state manageable.

------------------------------------------------------------
By following these steps, the TrustNonnullChecker uses system header annotations (and specific keyed methods in Objective‑C) to enforce and propagate non-null assumptions. This allows the analyzer to automatically treat certain pointers as nonnull, improve the accuracy of its nullability modeling, and subsequently remove unreachable or “dead” symbol implications.