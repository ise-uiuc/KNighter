Plan to detect unbounded copy_from_user into fixed-size local buffer

1. Program state
- Keep it simple but cover a common aliasing pattern (p = mybuf or p = &mybuf[0]):
  - REGISTER_MAP_WITH_PROGRAMSTATE(BufAliasMap, const MemRegion*, const VarDecl*)
    - Key: pointer variable’s MemRegion (the LHS region that will later be passed to copy_from_user).
    - Value: the VarDecl of the fixed-size local array that the pointer aliases.
- No other custom state/traits are required.

2. Helper checks/utilities (internal to the checker)
- isCopyFromUser(const CallEvent &Call):
  - Return true if callee name is one of: "copy_from_user", "__copy_from_user" (extendable if needed).
- getArrayFromDestExpr(const Expr *Dest, const VarDecl *&ArrVD, llvm::APInt &ArrSize, CheckerContext &C):
  - Try direct array:
    - If getArraySizeFromExpr(ArrSize, Dest) succeeds:
      - Extract VarDecl from the DeclRefExpr (dyn_cast<DeclRefExpr>(Dest->IgnoreImpCasts())->getDecl()) into ArrVD.
      - Return true.
  - Try alias via program state:
    - If direct fails, get MemRegion for Dest via getMemRegionFromExpr(Dest, C).
    - Lookup this region in BufAliasMap. If found, ArrVD = mapped VarDecl. Get ArrSize from ArrVD’s type (ConstantArrayType).
    - Return true if resolved; else false.
- lenExprIsConstantAndSafe(const Expr *LenE, const llvm::APInt &ArrSize, CheckerContext &C):
  - If EvaluateExprToInt succeeds, return true if value <= ArrSize, false if > ArrSize (reportable).
- lenExprLooksUnboundedUserCount(const Expr *LenE, const VarDecl *MaybeParam, const VarDecl *ArrVD, CheckerContext &C):
  - Goal: detect the specific pattern that LenE directly uses the unbounded size parameter (e.g., nbytes) and is not clamped.
  - Steps:
    - If LenE is DeclRefExpr to a ParmVarDecl PVD, and PVD’s name is one of {"nbytes","count"} (optionally include {"len","length","size"} if you wish), return true (likely unbounded).
    - Else, use ExprHasName:
      - If ExprHasName(LenE, "nbytes") or ExprHasName(LenE, "count") is true, AND
      - ExprHasName(LenE, "min") is false (to avoid flagging min(nbytes, ...) clamps), then return true.
    - Additional suppression:
      - If ArrVD is known, and LenE source contains "sizeof(" and contains ArrVD->getName(), consider it “clamped,” return false.
    - Otherwise return false.

3. Callback: checkBind (track simple pointer-to-array aliases)
- Goal: map a pointer variable to a local array when we see statements like:
  - p = mybuf; or p = &mybuf[0]; or char *p = mybuf; etc.
- Implementation:
  - On each binding, obtain LHS MemRegion from Loc.getAsRegion(). If not a MemRegion, bail.
  - Inspect Val.getAsRegion():
    - If it is a SubRegion/ElementRegion/VarRegion that ultimately bases on a VarRegion of a VarDecl with ConstantArrayType, record alias:
      - BufAliasMap = State->set<BufAliasMap>(LHSRegion, ArrVarDecl).
  - Also handle array-to-pointer decay:
    - If Val is a loc::MemRegionVal whose region is a VarRegion/ElementRegion corresponding to an array (base VarRegion is the array VarDecl), record same mapping.
  - Only track if ArrVarDecl is a local variable (VD->isLocalVarDecl()) and has ConstantArrayType.

4. Callback: checkPreCall (flag the bug at the point of copy_from_user)
- Identify the target call:
  - If !isCopyFromUser(Call), return.
- Extract arguments:
  - DestE = Call.getArgExpr(0), LenE = Call.getArgExpr(2).
- Resolve destination as a fixed-size local array:
  - VarDecl *ArrVD; llvm::APInt ArrSize;
  - If !getArrayFromDestExpr(DestE, ArrVD, ArrSize, C): return (we only flag array cases).
- Quick constant safety check:
  - If lenExprIsConstantAndSafe(LenE, ArrSize, C) is true, return (safe).
  - If it evaluates to a constant > ArrSize, report immediately (overflow with constant length).
- Heuristic for unbounded length:
  - Optionally identify the function context and the size parameter:
    - const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl()).
    - If FD has a ParmVarDecl named "nbytes" or "count", pass it as MaybeParam to lenExprLooksUnboundedUserCount (not strictly required, but can improve precision).
  - If lenExprLooksUnboundedUserCount(LenE, MaybeParam, ArrVD, C) is true:
    - Report bug: “copy_from_user length not clamped to destination buffer size”
- Bug reporting:
  - Generate a non-fatal error node with generateNonFatalErrorNode().
  - Use std::make_unique<PathSensitiveBugReport> with a short message:
    - “copy_from_user into fixed-size buffer uses unbounded user length”
  - Add a note range on DestE or ArrVD’s declaration if helpful.

5. Callback: checkPostStmt (optional; no-op)
- Not needed for this pattern.

6. Callback: checkBranchCondition, checkLocation, evalCall, etc.
- Not needed.

7. Notes on precision and suppression
- By requiring:
  - Destination is a fixed-size local array, and
  - Length expression directly references “nbytes” (or “count”) and does not contain “min(”,
  the checker aligns closely with the kernel write-handler pattern and minimizes false positives.
- The simple alias tracking in checkBind allows catching the common p = mybuf; followed by copy_from_user(p, buf, nbytes); case.
- The checker intentionally does not attempt deep dataflow for computed variables (e.g., bsize) to keep it simple and robust; thus, it avoids flagging when bsize is used instead of nbytes.

8. Summary of detection criteria
- Call to copy_from_user/(__copy_from_user).
- Destination resolves to a local fixed-size array (or a pointer proven to alias such an array).
- Length argument:
  - Is a constant > array size -> report, OR
  - References the unbounded user count parameter (typically “nbytes” or “count”) and does not appear to be clamped via min/sizeof -> report.

This plan uses the provided utility functions:
- getArraySizeFromExpr for extracting array bounds,
- EvaluateExprToInt to evaluate constant lengths,
- getMemRegionFromExpr and program state map for simple aliasing,
- ExprHasName to heuristically detect use of “nbytes” and absence of “min”/“sizeof”.
