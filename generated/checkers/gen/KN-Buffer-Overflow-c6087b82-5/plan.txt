Plan

1. Program State
   - No custom program state is required. This checker is a local syntactic/semantic validation around a single call site of copy_from_user(). Keep it stateless to stay simple and robust.

2. Callbacks
   - Use only checkPreCall. Optionally (non-essential) use checkEndFunction to verify the returned value matches the clamped length if you decide to enforce the “use bounded length for return value” as well.

3. checkPreCall: Detect unbounded copy_from_user into a fixed-size buffer
   - Goal: When encountering copy_from_user(dst, src, len), warn if len is not provably bounded by the size of the destination fixed-size buffer (ideally sizeof(buf) - 1 when later used as string).
   - Steps:
     1) Match function:
        - If callee name is "copy_from_user" (via Call.getCalleeIdentifier()->getName()).
        - Require exactly 3 arguments; extract:
          - DestExpr = Call.getArgExpr(0)
          - LenExpr  = Call.getArgExpr(2)
     2) Identify a fixed-size destination buffer:
        - Use getArraySizeFromExpr(ArraySize, DestExpr) to obtain a constant array size. If this fails (destination is not a constant array, e.g., pointer param), skip to avoid false positives.
        - Save DestVarName if possible:
          - If DestExpr is DeclRefExpr to a VarDecl, get VD->getName().
     3) Determine if the length argument is already clamped (fast textual/structural checks):
        - If EvaluateExprToInt(EvalRes, LenExpr, C) succeeds:
          - If EvalRes <= ArraySize (treat as safe). If you want to enforce string semantics, use ArraySize - 1 as the bound.
          - Otherwise, report.
        - Else, try to infer a symbolic upper bound:
          - Extract the SVal of LenExpr and its SymbolRef; use inferSymbolMaxVal(Sym, C).
          - If maxVal exists and maxVal <= ArraySize (or ArraySize - 1 for string semantics), treat as safe. Otherwise continue checks.
        - Else, try to detect common clamp idioms by inspecting the expression text and structure:
          - If ExprHasName(LenExpr, "min", C) or ExprHasName(LenExpr, "min_t", C) or ExprHasName(LenExpr, "min3", C) or ExprHasName(LenExpr, "clamp", C):
            - If also ExprHasName(LenExpr, "sizeof", C) and (DestVarName is known and ExprHasName(LenExpr, ("sizeof(" + DestVarName + ")").str(), C)), treat as safe.
            - Else if ExprHasName(LenExpr, "sizeof", C) without DestVarName match, conservatively treat as safe (to reduce false positives), but this is optional; tighter: require sizeof to mention the exact destination buffer name if available.
        - Else, if LenExpr is a DeclRefExpr to a local variable (e.g., bsize):
          - Inspect the VarDecl initializer if present:
            - If it contains min/min_t/min3/clamp and sizeof(DestVarName), treat as safe.
            - If it is a constant and <= ArraySize (or -1 for string semantics), treat as safe.
          - If no initializer or not conclusive, proceed to warn (the most common unsafe pattern passes a parameter like nbytes unchanged).
     4) Reporting:
        - If none of the above “safe” conditions hold, emit a bug:
          - Message: "copy_from_user length not clamped to destination buffer size"
          - Use a PathSensitiveBugReport.
          - Highlight the call expression, the destination argument, and the length argument as interesting sources.
          - Provide a short fix-it hint in the description: "Clamp length: min(nbytes, sizeof(buf) - 1)".

4. Optional enhancement (return value consistency): checkEndFunction
   - Purpose: If you enforced and detected clamping (e.g., bsize) and the function returns the original unbounded parameter (e.g., nbytes), flag a secondary advisory.
   - Simplest approach without program state:
     - Within checkPreCall when you detect a safe clamp via a variable (e.g., LenExpr is DeclRefExpr to var ‘bsize’), store the SourceRange or the identifier name of this var in a small local set keyed by the current function (could be a static map keyed by LCtx function pointer). This is optional but requires minimal state. Alternatively, skip this feature to keep the checker purely stateless.
     - In checkEndFunction, if the ReturnStmt returns a DeclRefExpr of a function parameter (like ‘nbytes’) and you previously observed a clamped variable used as copy length in this function, warn:
       - Message: "Function returns unbounded length; return the clamped length used for copy"
     - Keep this as a low-priority note. It’s not required for detecting the overflow.

5. Utilities to use
   - getArraySizeFromExpr to obtain fixed buffer size from the destination expression.
   - EvaluateExprToInt for constant-length expressions.
   - inferSymbolMaxVal for symbolic length upper-bound reasoning.
   - ExprHasName to detect min/min_t/min3/clamp/sizeof patterns and check whether sizeof references the destination buffer variable.
   - findSpecificTypeInParents/Children are not necessary for the core detection, so avoid unless you add extra context checks.

6. False-positive control
   - Only warn when:
     - Destination is a constant-sized array (we know the bound), and
     - The length argument is not provably bounded by that array’s size through constant evaluation, symbolic upper bound, or clear min()/sizeof() idioms.
   - This keeps the checker precise and focused on the pattern in the provided patch.

7. Summary of minimal implementation
   - No program state traits/maps.
   - One core callback: checkPreCall.
   - Logic:
     - Match copy_from_user.
     - Get dest array size; if unknown, skip.
     - Assess len boundedness:
       - Constant <= size (or size - 1) → safe.
       - Symbolic max <= size (or size - 1) → safe.
       - Len contains min()/sizeof(dest) clamp idiom → safe.
       - Len is var with initializer using min()/sizeof(dest) → safe.
       - Otherwise → report.
   - Short, clear report message.
