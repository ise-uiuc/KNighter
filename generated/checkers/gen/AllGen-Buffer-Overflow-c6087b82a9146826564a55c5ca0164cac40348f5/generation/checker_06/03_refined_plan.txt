Plan

1) Program state
- Use one program state map to reduce false positives by tracking variables that were previously clamped to a specific array size.
  - REGISTER_MAP_WITH_PROGRAMSTATE(SizeBoundMap, const MemRegion*, const MemRegion*)
    - Key: MemRegion of a scalar/size variable used as a length/count.
    - Value: MemRegion of the array it was bounded to (e.g., via sizeof(array) or min(..., sizeof(array))).

2) Callbacks to use
- checkPreCall: Detect unsafe copy_from_user calls.
- checkBind: Learn when a size variable is clamped to an array’s size (via sizeof/min), and propagate that information through assignments/initializers.

3) checkPreCall: detect unbounded copy_from_user into fixed-size buffers
- Identify the target function:
  - If Call.getCalleeIdentifier()->getName() != "copy_from_user", return.
- Extract arguments:
  - DestArg = Call.getArgExpr(0)
  - CountArg = Call.getArgExpr(2)
- Find the destination array and its size:
  - Use findSpecificTypeInChildren<DeclRefExpr>(DestArg) to get the underlying DeclRefExpr of the buffer variable (handles mybuf, &mybuf[0], mybuf + 0, etc.).
  - If no DeclRefExpr found, return (we only warn for actual fixed-size arrays).
  - Get the array size with getArraySizeFromExpr(ArraySize, DeclRefExpr).
    - If it’s not a ConstantArrayType, return.
  - Optionally reduce false positives by restricting to character arrays:
    - From the ConstantArrayType, fetch element type and only proceed if it’s a character type (char, unsigned char).
- Determine if the count is safely bounded:
  - If EvaluateExprToInt(EvalRes, CountArg, C) succeeds:
    - If EvalRes <= ArraySize: consider safe, return.
    - Else: definitely unsafe, report.
  - Else (non-constant CountArg), apply progressively more conservative safeness checks:
    - Textual clamp checks using ExprHasName on CountArg:
      - If ExprHasName(CountArg, "sizeof") AND ExprHasName(CountArg, <bufName>) => safe, return.
      - If ExprHasName(CountArg, "min") OR ExprHasName(CountArg, "min_t"), AND ExprHasName(CountArg, "sizeof"), AND ExprHasName(CountArg, <bufName>) => safe, return.
        - Note: <bufName> is from DeclRefExpr->getDecl()->getNameAsString().
    - State-based clamp checks via SizeBoundMap:
      - Get CountArg’s MemRegion with getMemRegionFromExpr(CountArg, C). If non-null:
        - Look up in State->get<SizeBoundMap>(CountRegion). If present and equals DestArrayRegion (use getMemRegionFromExpr on the DeclRefExpr for the array), consider safe, return.
- If none of the above safeness checks pass, report:
  - Message: "Unbounded copy_from_user into fixed-size buffer; clamp length to sizeof(buf)-1"
  - Create a non-fatal error node and emit a PathSensitiveBugReport. Add the call’s source range as the primary location.

4) checkBind: learn “count” variables clamped by sizeof(array)
- Goal: Populate SizeBoundMap so that later calls passing a pre-clamped variable are not flagged.
- For S in checkBind:
  - Extract LHS variable region:
    - If Loc is a loc::MemRegionVal, get LHSRegion. If null, return.
  - Find the RHS expression from S:
    - If S is a BinaryOperator with assignment, RHS = B->getRHS().
    - Else if S is a DeclStmt with initializer, for each VarDecl with init, RHS = VD->getInit().
    - Otherwise, return.
  - Try to detect if RHS clamps to a specific array:
    - Find an array DeclRefExpr on RHS: ArrayDRE = findSpecificTypeInChildren<DeclRefExpr>(RHS).
    - Verify it is a constant array using getArraySizeFromExpr(ArraySize, ArrayDRE). If false, skip (we only care about fixed-size buffers).
    - Heuristic safety patterns on RHS:
      - If ExprHasName(RHS, "sizeof") AND ExprHasName(RHS, ArrayDRE->getDecl()->getName()) => likely bounded.
      - Optionally, also accept when ExprHasName(RHS, "min") OR ExprHasName(RHS, "min_t") alongside the conditions above.
    - If bounded, set SizeBoundMap[LHSRegion] = ArrayRegion where ArrayRegion = getMemRegionFromExpr(ArrayDRE, C).
  - Propagate previously learned bounds through aliases:
    - If RHS is a DeclRefExpr of a scalar variable (count-like) whose MemRegion is in SizeBoundMap (i.e., X = Y; and Y was known bounded to array A), then set SizeBoundMap[LHSRegion] = SizeBoundMap[RHSRegion].
- Do not over-propagate through arbitrary expressions; only propagate:
  - Direct sizeof/min expressions involving a fixed-size array.
  - Direct copies from a variable that is already in SizeBoundMap.

5) Notes and heuristics to minimize false positives
- Only warn when destination is a fixed-size array (ConstantArrayType).
- Prefer restricting to character arrays for this checker’s intent (copying user data into char buffers).
- Treat expressions explicitly mentioning sizeof(buf) (and optionally min/min_t) as safe.
- Treat explicitly constant CountArg <= sizeof(buf) as safe.
- Recognize precomputed clamped variables via SizeBoundMap mapping to the same array.
- Do not require “- 1” to be present; copying up to sizeof(buf) is acceptable for raw bytes. The message can suggest sizeof(buf) - 1 to hint at string usage without enforcing it.

6) Utility functions used
- findSpecificTypeInChildren<DeclRefExpr>(Expr): to recover the underlying array from complex address expressions.
- getArraySizeFromExpr(ArraySize, Expr): to extract constant array size.
- ExprHasName(Expr, "sizeof"/"min"/bufName, C): to recognize textual clamp patterns.
- getMemRegionFromExpr(Expr, C): to build/compare MemRegions for SizeBoundMap.
- EvaluateExprToInt(EvalRes, CountArg, C): to detect constant counts.

7) Bug reporting
- Create a checker-local BugType (e.g., "Unbounded user copy into fixed-size buffer").
- In checkPreCall when issuing a report, generate a non-fatal error node and emit a PathSensitiveBugReport with a concise message:
  - "Unbounded copy_from_user into fixed-size buffer; clamp length to sizeof(buf)-1"
- Point to the copy_from_user call and, if useful, add a note pointing to the destination buffer declaration (DeclRefExpr location).
