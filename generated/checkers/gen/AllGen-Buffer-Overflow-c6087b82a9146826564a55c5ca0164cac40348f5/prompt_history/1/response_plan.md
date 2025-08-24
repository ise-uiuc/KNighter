Plan

1. No custom program states
   - Keep it simple and path-insensitive. Do not introduce program state maps/traits initially.
   - Rely on direct AST/expr inspection at the call site and light-weight value reasoning via:
     - getArraySizeFromExpr
     - findSpecificTypeInChildren
     - EvaluateExprToInt
     - inferSymbolMaxVal
     - ExprHasName

2. Callback selection
   - Use only checkPreCall for the first iteration.
   - Optional enhancement (if needed): add checkBind to recognize a common clamp assignment pattern and cache a “clamped” fact for the specific size variable and buffer.

3. checkPreCall (core detection)
   - Goal: Flag calls to copy_from_user(dst, src, nbytes) where:
     - dst is a fixed-size array in the current scope, and
     - nbytes is not provably bounded to dst’s size (preferably <= sizeof(dst) - 1).
   - Steps:
     1) Identify target function
        - If Call.getCalleeIdentifier()->getName() != "copy_from_user", return.
     2) Extract arguments
        - Arg0 = destination expression (ToExpr)
        - Arg1 = source (unused)
        - Arg2 = size expression (NExpr)
     3) Determine the destination buffer size
        - Try getArraySizeFromExpr(ArraySize, ToExpr).
        - If that fails (due to decay or &buf[0]), call findSpecificTypeInChildren<DeclRefExpr>(ToExpr) to find a DeclRefExpr referencing the array, then call getArraySizeFromExpr on that DeclRefExpr.
        - If still not found, return (we only warn when destination is a compile-time fixed-size array).
        - Compute Bound = ArraySize - 1 (to match kernel’s string use case and the target pattern).
     4) Try to prove the size argument is safe
        - Case A: Constant size
          - If EvaluateExprToInt(Const, NExpr) succeeds:
            - If Const <= Bound, OK -> return.
            - Else, report (unsafe).
        - Case B: Symbolic size with known maximum
          - Obtain SVal for NExpr; if it has a SymbolRef, call inferSymbolMaxVal(Sym, C).
          - If maxVal exists and maxVal <= Bound, OK -> return.
          - If maxVal > Bound or unknown, continue checking for syntactic clamp patterns.
        - Case C: Syntactic clamp pattern in the size expression itself
          - If ExprHasName(NExpr, "min", C) AND ExprHasName(NExpr, "sizeof", C):
            - Additionally, if we can get the destination variable name (from DeclRefExpr of dst), check ExprHasName(NExpr, DestVarName, C).
            - If true, consider it clamped -> return.
        - Case D: The size is a local variable with an initializer clamp
          - If NExpr is a DeclRefExpr to a VarDecl (e.g., bsize), try:
            - If VarDecl has an initializer Init:
              - If EvaluateExprToInt(Const, Init) succeeds and Const <= Bound -> return.
              - Else if ExprHasName(Init, "min", C) AND ExprHasName(Init, "sizeof", C) AND ExprHasName(Init, DestVarName, C) -> return.
        - If none of the above proves safety -> report.
     5) Emit report
        - Create a non-fatal error node and emit a PathSensitiveBugReport.
        - Message: "Unbounded copy_from_user into fixed-size buffer"
        - Point the primary range to Arg2 (size argument). Optionally, add a note range on Arg0 (destination).
        - Keep it short per Suggestions.

4. Optional enhancement: checkBind for clamp assignments (if you want to reduce false positives)
   - Rationale: handle patterns like:
     - bsize = min(nbytes, sizeof(buf) - 1);
     - or bsize set via conditional clamp: if (nbytes > sizeof(buf)-1) bsize = sizeof(buf)-1; else bsize = nbytes;
   - Minimal approach:
     - REGISTER_MAP_WITH_PROGRAMSTATE(ClampOkMap, const MemRegion*, const MemRegion*)
       - Map: size variable region -> destination buffer region that the clamp ties to.
     - In checkBind:
       - When binding to a region corresponding to an integer variable (LHS), analyze RHS:
         - If ExprHasName(RHS, "min", C) AND ExprHasName(RHS, "sizeof", C):
           - Try to find a DeclRefExpr for the destination array inside RHS via findSpecificTypeInChildren<DeclRefExpr>() and ensure it refers to a ConstantArray VarDecl.
           - If found, insert ClampOkMap[LHSRegion] = DestArrayRegion.
     - In checkPreCall:
       - If Arg2 is a variable, look up ClampOkMap for its region. If present and DestArrayRegion equals the destination array region for Arg0, then consider safe and return.
   - This enhancement keeps state small and highly targeted to this bug pattern.

5. Notes and heuristics
   - Only warn when destination is a compile-time constant-sized array; skip otherwise to avoid false positives.
   - Prefer Bound = sizeof(buf) - 1 to align with the kernel’s pattern in the patch. This matches the “string” expectation that follows many debugfs writes.
   - Do not attempt to validate the return value (nbytes vs bsize) for this checker; focus strictly on the overflow risk at copy_from_user.
   - Keep the checker conservative: if safety cannot be proven by any of the checks above, emit the warning.
