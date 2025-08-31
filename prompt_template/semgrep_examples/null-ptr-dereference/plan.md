### Plan

1. **Pattern Detection:**
   - Use semgrep to identify code patterns where array/pointer elements are dereferenced without null checks
   - Target pattern: `if ($PPS[$ID]->$FIELD == false) { ... }`
   - Exclude safe patterns that already include null checks: `if ($PPS[$ID] == nullptr || $PPS[$ID]->$FIELD == false) { ... }`

2. **Static Analysis Approach:**
   - **Pattern Matching:** Identify direct field access on array elements without prior null validation
   - **Context Analysis:** Ensure the pattern occurs in conditional statements where the dereference is the primary condition
   - **Exclusion Rules:** Skip cases where null checks are already present in the same condition

3. **Vulnerability Validation:**
   - Verify that the array element (`$PPS[$ID]`) can potentially be null
   - Confirm that the field access (`->$FIELD`) occurs without prior validation
   - Check if the pattern is in a context where null values are possible

4. **Fix Strategy:**
   - **Add Null Check:** Insert null pointer validation before field access
   - **Safe Pattern:** Transform `if (ptr->field == value)` to `if (ptr != nullptr && ptr->field == value)`
   - **Defensive Programming:** Implement consistent null checking patterns throughout the codebase

5. **Recommended Fix:**
   ```cpp
   // Before (vulnerable):
   if (pps[id]->field == false) {
       // ... processing code
   }
   
   // After (safe):
   if (pps[id] != nullptr && pps[id]->field == false) {
       // ... processing code
   }
   ```

6. **Prevention Measures:**
   - Establish coding standards requiring null checks before pointer dereference
   - Use static analysis tools to catch similar patterns during development
   - Implement unit tests that verify null pointer handling
   - Consider using smart pointers or optional types where appropriate
