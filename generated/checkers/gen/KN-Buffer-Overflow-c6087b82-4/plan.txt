1) Program state customizations
- REGISTER_MAP_WITH_PROGRAMSTATE(SizeBoundMap, const MemRegion*, uint64_t)
  - Tracks integer variables that hold a bounded length (upper bound) derived from sizeof(array) (optionally minus a small constant) or a min(...) with such sizeof bound.
- REGISTER_MAP_WITH_PROGRAMSTATE(PtrToArraySizeMap, const MemRegion*, uint64_t)
  - Tracks pointer variables that alias a fixed-size array (e.g., p = mybuf; or p = &mybuf[0];), recording the array’s size.
- No other traits needed.

2) Callback selection and implementation steps

A) checkPreCall (detect unsafe copy_from_user invocations)
- Goal: Warn when copy_from_user(dst, src, len) copies into a fixed-size stack array without capping len by the array size.
- Steps:
  1) Identify target calls:
     - If Call.getCalleeIdentifier()->getName() != "copy_from_user", return.
  2) Extract arguments:
     - DestExpr = Call.getArgExpr(0)->IgnoreImpCasts()
     - LenExpr  = Call.getArgExpr(2)->IgnoreImpCasts()
  3) Determine destination buffer size A (in bytes):
     - Try getArraySizeFromExpr(ArraySize, DestExpr). This works if DestExpr is a DeclRefExpr (array decays to pointer).
     - Else if DestExpr is UnaryOperator (‘&’) of an ArraySubscriptExpr (e.g., &mybuf[0]):
       - Get base of ArraySubscriptExpr, find DeclRefExpr and call getArraySizeFromExpr on that.
       - You can use findSpecificTypeInChildren<DeclRefExpr>(DestExpr) and then getArraySizeFromExpr on it.
     - Else if DestExpr is a pointer variable:
       - Get its MemRegion via getMemRegionFromExpr; lookup in PtrToArraySizeMap. If found, use that size.
     - If A is still unknown, bail out (to avoid false positives).
  4) Decide if len is safely bounded:
     - Case 1: LenExpr is a compile-time constant:
       - If EvaluateExprToInt succeeds and value <= A, safe; else report.
     - Case 2: LenExpr syntactically expresses a bound using sizeof of the destination:
       - Use ExprHasName(LenExpr, "sizeof(") and also ensure it contains the array name if available (from the DeclRefExpr found for the destination). If true, mark safe.
     - Case 3: LenExpr is an identifier (DeclRefExpr) to a variable with a known bound:
       - Get MemRegion of LenExpr. If SizeBoundMap has an entry (Bound) and Bound <= A, safe; else not proven safe.
     - Case 4: Use constraint manager upper bound:
       - Extract symbol for LenExpr (C.getSVal(LenExpr,...).getAsSymbol()); call inferSymbolMaxVal. If present and <= A, safe; else not proven safe.
     - If none of the above prove safety, emit a report.
  5) Reporting:
     - Create a non-fatal error node and emit a PathSensitiveBugReport with a short message:
       - "copy_from_user length not capped by destination size"
     - Highlight the call expression.

B) checkPostStmt (DeclStmt) (record bounded sizes during variable initialization)
- Goal: Populate SizeBoundMap for variables initialized from min(...) with sizeof array, or directly from sizeof(array) +/- c.
- Steps:
  1) For each VarDecl V with initializer Init:
     - Only consider integer/size_t-like variables (e.g., V->getType()->isIntegerType()).
  2) Analyze Init to detect bound patterns:
     - If source text contains "min(" AND "sizeof(":
       - We treat this as a capped bound. Attempt to compute the maximum cap:
         - Find a DeclRefExpr inside Init referring to an array variable (use findSpecificTypeInChildren<DeclRefExpr>(Init)).
         - Call getArraySizeFromExpr to obtain array size A if that DeclRefExpr’s type is ConstantArrayType.
         - Determine if source contains "- 1" (ExprHasName(Init, "- 1") or "-1"); if yes, Bound = A - 1; else Bound = A.
       - If A is found, store: SizeBoundMap[Region(V)] = Bound.
     - Else if Init contains "sizeof(" (no min):
       - Similarly, detect an array DeclRefExpr; compute A; detect optional "- 1"; Bound = (A - 1) or A; store in SizeBoundMap.
     - Else if Init is a DeclRefExpr to another variable W:
       - If W has a bound in SizeBoundMap, copy it: SizeBoundMap[Region(V)] = SizeBoundMap[Region(W)].
  3) Do not emit reports here.

C) checkBind (propagate bounds on assignments and track pointer-to-array aliases)
- Goal: Keep SizeBoundMap and PtrToArraySizeMap updated when variables are assigned.
- Steps:
  1) If S is a BinaryOperator that’s an assignment (opKind is =, += not needed):
     - Let LHS be the assigned variable; get its MemRegion (only if it’s a variable region).
     - Let RHS be the assigned expression (binop->getRHS()).
  2) Propagate integer size bounds:
     - If LHS type is integer/size_t-like:
       - If RHS source contains "min(" and "sizeof(":
         - Find DeclRefExpr for an array inside RHS; compute A with getArraySizeFromExpr.
         - Determine optional "- 1" as above; Bound = (A - 1) or A.
         - Record: SizeBoundMap[Region(LHS)] = Bound.
       - Else if RHS contains "sizeof(":
         - Compute A similarly; detect "- 1"; record Bound.
       - Else if RHS is a DeclRefExpr to another integer variable with a known bound:
         - Copy bound: SizeBoundMap[Region(LHS)] = SizeBoundMap[Region(RHS)].
       - Else: do nothing (don’t clear previous info; allow later overwrites to replace).
  3) Track pointer-to-array alias for destination resolution:
     - If LHS type is a pointer (char*, void*, etc.):
       - If RHS refers to an array (DeclRefExpr of ConstantArrayType) or is &ArraySubscriptExpr based on an array:
         - Compute A using getArraySizeFromExpr (on array DeclRefExpr found in RHS).
         - Record: PtrToArraySizeMap[Region(LHS)] = A.

D) Optional: checkEndFunction / checkRegionChanges
- Not needed. Rely on the analyzer to drop maps at function boundaries automatically.

3) Heuristics and notes
- Destination array detection:
  - Prefer direct getArraySizeFromExpr on DeclRefExpr or on the DeclRefExpr found inside &arr[0] forms via findSpecificTypeInChildren.
  - Only report when destination size A is known (ConstantArrayType) and the destination originates from a local stack array (VarDecl->hasLocalStorage()) to reduce false positives.
- Len safety checks:
  - If the argument text contains "sizeof(" and contains the destination array’s name, consider it safe even without "- 1".
  - When using SizeBoundMap, accept as safe if Bound <= A.
  - When using constraint manager, accept as safe if inferred max <= A.
- Macros:
  - Use ExprHasName to detect "min(" and "sizeof(" from the source text, which stays intact before macro expansion. This handles kernel min() macro usage.
- Report message:
  - Keep it short and clear: "copy_from_user length not capped by destination size".

4) Summary of utility functions used
- getArraySizeFromExpr to get constant array sizes from DeclRefExprs.
- findSpecificTypeInChildren to locate DeclRefExpr or sizeof (UnaryExprOrTypeTraitExpr) deep inside complex expressions like &arr[0] or min macro expansions.
- EvaluateExprToInt to quickly accept constant length arguments.
- inferSymbolMaxVal to leverage constraint information when available.
- getMemRegionFromExpr to map expressions to regions for SizeBoundMap/PtrToArraySizeMap.
- ExprHasName to detect "min(" / "sizeof(" / "- 1" patterns in source text.

5) Minimal end-to-end flow
- As variables get initialized/assigned, record bounds (SizeBoundMap) or pointer-to-array aliases (PtrToArraySizeMap).
- On each copy_from_user call, derive the destination array size A; then verify the third argument is provably <= A via one of: constant evaluation, direct "sizeof(dest)" text, recorded bound, or inferred max; otherwise, emit a bug report.
