```
1. No need for custom program states.
2. Use checkPreCall to detect calls to strcpy:
   - In checkPreCall, check if the callee’s identifier is "strcpy". If not, return immediately.
3. Extract and analyze the destination argument:
   - Retrieve the first argument of the strcpy call (i.e. the destination pointer).
   - Use getMemRegionFromExpr to obtain its MemRegion.
   - Apply getArraySizeFromExpr on the destination expression. If it returns true, this confirms that the destination is a fixed-size array.
4. Report the unsafe use if the destination is a fixed-size buffer:
   - Since strcpy does not take the buffer size, mark this as a potential buffer overflow.
   - Emit a bug report using std::make_unique<PathSensitiveBugReport> (or BasicBugReport) with a short message like “Unsafe strcpy detected: potential buffer overflow.”
5. (Optional) Use checkBind if later pointer aliasing becomes relevant, but it is not necessary for this simple pattern.
```