1) Program state customization

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrToArrayMap, const MemRegion*, const MemRegion*)
  - Maps a pointer variable’s region (e.g., pbuf) to the MemRegion of the underlying fixed-size array (e.g., mybuf). This lets us recover the actual destination array when copy_from_user() is called with a pointer alias.

- REGISTER_MAP_WITH_PROGRAMSTATE(BoundedLenMap, const MemRegion*, const MemRegion*)
  - Maps an array’s MemRegion to a length variable’s MemRegion (e.g., bsize) that is known to be bounded by sizeof(array) (ideally via min(..., sizeof(array) - 1)). This suppresses false positives when the code computes a bounded length first and then passes that bounded variable to copy_from_user().


2) Callback selection and how to implement them

- checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const
  - Goal A: Track pointer-to-array aliases (PtrToArrayMap).
    - If S is an assignment or init (BinaryOperator ‘=’ or DeclStmt with initializer), analyze RHS.
    - Use findSpecificTypeInChildren<DeclRefExpr>(RHSExpr) to find a DeclRefExpr.
    - If the DeclRefExpr refers to a VarDecl whose type is ConstantArrayType (i.e., a fixed-size array), then:
      - Get the array MemRegion with getMemRegionFromExpr on that DeclRefExpr.
      - Get the LHS MemRegion (pointer variable) from Loc.getAsRegion().
      - If both exist and the array element type is a character type (char/signed char/unsigned char), record PtrToArrayMap[LHSRegion] = ArrayRegion in the state.
        - Heuristic for character type: check the ConstantArrayType’s element type to be Char/SChar/UChar.

  - Goal B: Track “bounded length” variables (BoundedLenMap).
    - For the same assignment/init, inspect RHS to see if it looks like a min(...) involving sizeof(the same array).
      - Detect presence of sizeof(array) in RHS:
        - Use findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHSExpr) and see if any is UETT_SizeOf, and its argument is a DeclRefExpr to a ConstantArrayType VarDecl (this is the target array).
      - Reduce false positives by also checking if ExprHasName(RHSExpr, "min") or ExprHasName(RHSExpr, "min_t") (kernel min macros). If both “sizeof(array)” and “min/min_t” are found in RHS, assume RHS computes a bounded length for that array.
      - If matched:
        - Get LHS MemRegion from Loc.getAsRegion() (the length variable, e.g., bsize).
        - Get the array MemRegion with getMemRegionFromExpr on the DeclRefExpr found in the sizeof() argument.
        - Record BoundedLenMap[ArrayRegion] = LHSRegion.

- checkPreCall(const CallEvent &Call, CheckerContext &C) const
  - Identify calls to copy_from_user:
    - If Call.getCalleeIdentifier() name equals "copy_from_user", proceed.
  - Extract and analyze arguments:
    - Arg0 (destination), Arg1 (user src), Arg2 (length).
  - Determine the fixed-size array for Arg0:
    - First try to find a DeclRefExpr to an array in Arg0 with findSpecificTypeInChildren<DeclRefExpr>(Arg0). If found and the VarDecl type is ConstantArrayType with character element type:
      - Use getArraySizeFromExpr(ArraySize, DeclRefExpr) to retrieve the size.
      - Also get the array MemRegion via getMemRegionFromExpr(DeclRefExpr, C).
    - If no array DRE is found, try pointer-to-array alias:
      - Get Arg0 MemRegion via getMemRegionFromExpr(Arg0, C). If it maps in PtrToArrayMap to an ArrayRegion, use that ArrayRegion.
      - From that array’s DeclRefExpr (child of the defining statement if available) or directly from the VarDecl type, retrieve the ConstantArrayType size (use getArraySizeFromExpr if you can still obtain a DeclRefExpr; otherwise use the VarDecl’s ConstantArrayType).
    - If we cannot determine a fixed-size array for the destination, bail (no report).

  - Decide whether Arg2 (length) is safely bounded:
    - Case 1: Constant length
      - Try EvaluateExprToInt(Val, Arg2, C).
      - If constant and Val <= ArraySize, consider safe; if Val > ArraySize, report bug.
    - Case 2: Bounded length variable
      - Get Arg2 MemRegion via getMemRegionFromExpr(Arg2, C). If it exists and equals BoundedLenMap[ArrayRegion], consider safe.
    - Case 3: Inline sizeof(array) bound
      - If Arg2 contains a sizeof() referencing the same discovered array (findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(Arg2) + check DeclRefExpr to the same array), consider safe.
    - Otherwise: length is not provably bounded -> report bug.

  - Reporting:
    - Create a non-fatal error node (generateNonFatalErrorNode) and emit a PathSensitiveBugReport with a short message, e.g.:
      - "copy_from_user length not capped to destination buffer size"
    - Optionally add a note on the destination buffer name and size to the report path.

- Optional helper logic (private utility methods inside the checker)
  - isCharArray(const VarDecl *VD):
    - Returns true if VD->getType() is ConstantArrayType with element type char/signed char/unsigned char.
  - getArrayInfoFromExpr(const Expr *E, CheckerContext &C, const VarDecl *&ArrayVD, const MemRegion *&ArrayReg, llvm::APInt &ArraySize):
    - Tries to extract the underlying array from E (direct or via PtrToArrayMap), its VarDecl, MemRegion, and constant size using getArraySizeFromExpr. Uses findSpecificTypeInChildren<DeclRefExpr>(E) and getMemRegionFromExpr, plus PtrToArrayMap lookup in fallback.
  - lenExprUsesSizeofArray(const Expr *Len, const VarDecl *ArrayVD):
    - Scans for UnaryExprOrTypeTraitExpr of kind sizeof, and checks if any argument refers to ArrayVD.
  - sameArrayVar(const VarDecl *A, const VarDecl *B):
    - Compare VarDecl pointers.

Notes and heuristics

- This checker is path-sensitive enough without tracking function signatures; focusing on copy_from_user() with destination as a local fixed-size char array significantly reduces false positives while catching the intended kernel pattern.
- The BoundedLenMap requires both sizeof(array) and “min/min_t” text in RHS when learning a bounded length variable, to avoid incorrectly assuming safety for arbitrary expressions that mention sizeof(array).
- Alias tracking via PtrToArrayMap covers common "char mybuf[64]; char *pbuf = &mybuf[0]; copy_from_user(pbuf, ...)" patterns.
- You do not need to implement additional callbacks (BranchCondition, Location, etc.) for this checker.
- Keep the bug message short and clear as required.
