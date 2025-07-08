/* 
Plan:
1. Hook the freeing call using checkPreCall:
   • Use the checkPreCall callback to intercept all function calls.
   • In the callback, extract the caller’s callee identifier (using Call.getCalleeIdentifier() with getNameAsString()).
   • Compare the obtained name with the literal string "metadata_dst_free".

2. Validate the free call context:
   • Once a call to metadata_dst_free() is detected, retrieve the function argument (which should be the shared metadata object).
   • Optionally, verify that the argument’s source text does not indicate that its inner field “dst” is being used (this can be done with the utility function ExprHasName() checking for "->dst" in the expression).
   • (If desired, this extra step ensures that we are not misreporting valid use of dst_release() as the bug pattern.)

3. Report the bug:
   • If metadata_dst_free() is used (and the argument is not appropriately dereferenced to its ‘dst’ subobject), emit a bug report.
   • Use a short and clear message such as "Freeing shared metadata with metadata_dst_free() can lead to use‐after‐free; use dst_release() instead."
   • Employ std::make_unique<BasicBugReport> (or PathSensitiveBugReport) to generate the report.

4. Program state considerations:
   • No additional program state maps (e.g., for pointer aliasing) are required since we are simply checking the call’s callee name.
   • Hence, no customization via REGISTER_MAP_WITH_PROGRAMSTATE or similar mechanisms is necessary for this simple check.

Summary:
• In checkPreCall, hook every call event.
• Identify if the function name equals "metadata_dst_free" by extracting its identifier string.
• Optionally, check that its argument does not contain a dereference of the "dst" field.
• If the check is positive, emit a bug report with a concise message indicating that the shared metadata object is being freed directly, recommending the use of dst_release() instead.
*/
