Plan

1. Program state customization
- REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenMap, const MemRegion*, const MemRegion*)
  - Purpose: For a specific destination array region (key), remember the MemRegion of a length variable (value) that was computed using sizeof(that array). This lets us accept patterns like bsize = min(nbytes, sizeof(mybuf) - 1); copy_from_user(mybuf, buf, bsize).
- (Optional, only if you want a fallback) REGISTER_SET_WITH_PROGRAMSTATE(BoundedLenSyms, SymbolRef)
  - Purpose: Mark symbols that are computed using any sizeof(...) (not necessarily tied to a particular array). Use only as a weak heuristic to reduce false positives if ArraySafeLenMap didn’t catch a pairing.

2. Helper detection utilities (simple functions inside the checker)
- isCopyFromUser(const CallEvent &Call)
  - Return true if callee name is one of: "copy_from_user", "__copy_from_user", "raw_copy_from_user".
- getDestArrayInfo(const Expr *DstArg, CheckerContext &C, llvm::APInt &ArraySize, const MemRegion* &ArrReg, std::string &ArrName)
  - Try to identify the destination as a fixed-size array:
    - If getArraySizeFromExpr(ArraySize, DstArg) succeeds and getMemRegionFromExpr(DstArg, C) returns a region, set ArrReg and return true.
    - Also extract array name from DstArg: if it’s a DeclRefExpr VarDecl, use getNameAsString.
- exprContainsSizeofOfArray(const Expr *E, StringRef ArrName, CheckerContext &C)
  - Returns true if:
    - ExprHasName(E, "sizeof", C) and the source text contains ArrName, i.e., ExprHasName(E, ArrName, C).
    - Or AST-based search finds a UnaryExprOrTypeTraitExpr with kind UETT_SizeOf whose argument is a DeclRefExpr of the same VarDecl as DstArg (use findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr> and inspect the argument).
- getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C, const MemRegion* &LenReg, SymbolRef &LenSym)
  - Obtain the MemRegion of the length expression if it’s a variable (DeclRefExpr) and its SymbolRef from the State. Either can be used to match against ArraySafeLenMap or BoundedLenSyms.

3. Track “safe length” variables built from sizeof(array) (checkBind)
- Callback: checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
  - Only handle assignment statements:
    - If S is a BinaryOperator with isAssignmentOp():
      - Get LHS as a variable region (MemRegion* LHSReg). If not a simple local/global/param variable region, skip.
      - Inspect RHS Expr:
        - Search for UnaryExprOrTypeTraitExpr (kind == UETT_SizeOf) in children:
          - If it references a DeclRefExpr to a VarDecl with ConstantArrayType, get:
            - The destination array’s MemRegion* ArrReg (using getMemRegionFromExpr on that DeclRefExpr).
            - Update program state: ArraySafeLenMap = ArraySafeLenMap.set(ArrReg, LHSReg).
        - As a weak fallback (optional): if RHS text contains "min" and "sizeof", mark the LHS symbol as bounded:
          - SymbolRef LHSym = State->getSValAsScalarOrLoc(LHSReg).getAsSymbol();
          - If LHSym, add to BoundedLenSyms.
  - Rationale:
    - This catches patterns like:
      - bsize = min(nbytes, sizeof(mybuf) - 1);
      - len = sizeof(buf) - 1;
      - safe = sizeof(buf) (not ideal for strings but still useful upper bound).
    - We pair a “safe length var” specifically with the array whose sizeof appeared.

4. Detect unsafe copy_from_user into a fixed-size array (checkPreCall)
- Callback: checkPreCall(const CallEvent &Call, CheckerContext &C) const
  - If not isCopyFromUser(Call), return.
  - Extract arguments:
    - Dst = Call.getArgExpr(0)
    - Len = Call.getArgExpr(2)
  - Identify destination array info:
    - If getDestArrayInfo(Dst, C, ArraySize, ArrReg, ArrName) fails, return (we only warn when we can prove it’s a fixed-size array).
    - Compute SafeCopyLimit = ArraySize - 1 (for string-like use) and also note ArraySize for general overflow checks.
  - Test for safety (short-circuit in the following order):
    1) If exprContainsSizeofOfArray(Len, ArrName, C) is true:
       - Consider SAFE (typical case: min(n, sizeof(buf) - 1) or sizeof(buf) - 1 in the arg directly).
    2) If Len is a DeclRefExpr and ArraySafeLenMap contains (ArrReg -> LenReg) where LenReg matches the Len argument’s region:
       - Consider SAFE.
    3) If Len has a known max:
       - If Len is a symbol, const llvm::APSInt *maxVal = inferSymbolMaxVal(LenSym, C).
       - If maxVal exists and maxVal <= SafeCopyLimit: SAFE.
       - If maxVal exists and maxVal > ArraySize: definitely dangerous. Report.
    4) If Len is a constant:
       - If constant > ArraySize: definitely dangerous. Report.
       - Else if constant <= SafeCopyLimit: SAFE.
       - Else (constant in (SafeCopyLimit, ArraySize]): For overflow it’s safe, but if you want to only focus on overflow, skip. If you also want to enforce “-1” for string scenarios, you may optionally warn; but to avoid noise, don’t warn for this case unless you know later string ops happen.
    5) Weak fallback (optional):
       - If Len’s symbol is in BoundedLenSyms: SAFE.
  - If none of the above marked SAFE, emit a warning:
    - This is the common pattern “copy_from_user(buf, user, nbytes)” where nbytes is unchecked. Report it as potential overflow.
  - Reporting:
    - Generate NonFatalErrorNode and create PathSensitiveBugReport with a short message:
      - "copy_from_user length not bounded by destination buffer size"
    - Add notes:
      - Point to Dst expression: "destination buffer here"
      - Point to Len expression: "length argument is not clamped (use min(n, sizeof(buf) - 1))"

5. Optional: Improve precision with branch detection (checkBranchCondition)
- Callback: checkBranchCondition(const Stmt *Condition, CheckerContext &C) const
  - Recognize simple clamps like:
    - if (len > sizeof(buf) - 1) len = sizeof(buf) - 1; (but full flow-sensitive modeling is complex).
  - For simplicity, skip implementing branch-based clamps unless you also record assignment in checkBind. The primary precision comes from checkBind recognizing RHS sizeof(...) when assigning the “safe length” variable.

6. Optional: Avoid false positives when destination is not an array
- If getDestArrayInfo fails (e.g., dst is a pointer or variable-sized object), do not warn.

7. Minimal function matching robustness
- isCopyFromUser should match at least "copy_from_user" and "__copy_from_user". If desired, include "raw_copy_from_user".
- Do not rely on min() being a CallExpr; in the kernel it’s a macro. Rely on:
  - Presence of sizeof(array) in the Len argument expression; or
  - A prior assignment that used sizeof(array) in RHS captured by checkBind.

8. Summary of callbacks to implement
- checkBind: Track assignments of size variables computed from sizeof(array) and store mapping ArraySafeLenMap[ArrReg] = LenVarReg. Optionally mark symbols containing min+sizeof as bounded in BoundedLenSyms.
- checkPreCall: Detect unsafe copy_from_user when arg0 is a fixed-size array and arg2 is not obviously bounded by sizeof(array) or a previously tracked safe variable, nor known bounded by constraints. Emit report.
- (Optional) checkBranchCondition: Skip or keep minimal; not required by this plan.

9. Notes on using provided utility functions
- getArraySizeFromExpr: Use on the destination argument to get fixed array size.
- getMemRegionFromExpr: Use to map both destination array and length variables to regions for state maps.
- EvaluateExprToInt: Try to evaluate Len as a constant when possible.
- inferSymbolMaxVal: Use to infer an upper bound for Len symbol for SAFE detection.
- ExprHasName: For simple textual checks on "sizeof" and "min" within an expression; use only as a heuristic. Prefer AST-based sizeof detection where possible.
- findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>: To detect UETT_SizeOf in RHS in checkBind and in Len expressions in checkPreCall.

10. Bug report messaging
- BugType: "Unbounded copy_from_user"
- Message: "copy_from_user length not bounded by destination buffer size"
- Single, short message; avoid long explanations. Add one or two notes to highlight the destination and length expressions.
