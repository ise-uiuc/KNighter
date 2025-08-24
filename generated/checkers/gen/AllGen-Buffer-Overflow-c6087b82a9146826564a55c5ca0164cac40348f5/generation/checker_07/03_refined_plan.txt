Plan

1. Program state
- No custom traits are necessary beyond two simple maps for aliasing and for marking suspicious buffers:
  - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
    - Key: pointer variable region.
    - Value: the ultimate base MemRegion of the underlying fixed-size array it aliases.
  - REGISTER_MAP_WITH_PROGRAMSTATE(UnboundedCopyMap, const MemRegion*, bool)
    - Key: base MemRegion of a fixed-size array.
    - Value: true indicates that the most recent copy_from_user() into this array was not proven bounded by sizeof(array)-1 (thus possible overflow and no guaranteed trailing NUL). Removing the key (or setting false) means safe/clean.

2. Helpers
- isCopyFromUser(const CallEvent &Call): return true if callee identifier name is "copy_from_user".
- isStringOp(const CallEvent &Call): return true for any of:
  - "strcmp", "strncmp", "strcasecmp", "strncasecmp", "strlen"
- getBaseRegionFromExpr(const Expr *E, CheckerContext &C):
  - Using getMemRegionFromExpr(E, C), then normalize with Region->getBaseRegion().
- getArraySizeForDestExpr(const Expr *DestE, llvm::APInt &ArrSz):
  - Try to find DeclRefExpr of the array via findSpecificTypeInChildren<DeclRefExpr>(DestE). If found, call getArraySizeFromExpr(ArrSz, DRE).
  - If DestE is an implicit array-to-pointer decay, still find DRE via the child traversal utility.
  - If Dest is an expression like &buf[0] or buf + 0, use the same approach; the child DeclRefExpr gives you the array VarDecl.
- getUpperBoundOfSizeArg(const Expr *SizeE, CheckerContext &C, llvm::APSInt &UB, bool &Known):
  - If EvaluateExprToInt(UB, SizeE, C) succeeds, Known = true.
  - Else, get SVal SV = State->getSVal(SizeE, C.getLocationContext()). If SV is a SymbolVal, query inferSymbolMaxVal(SymbolRef, C). If it returns non-null, set UB = *maxVal, Known = true. Otherwise Known = false.
- getArrayBaseForArg(const Expr *ArgE, CheckerContext &C):
  - 1) Try getBaseRegionFromExpr(ArgE, C), call it R.
  - 2) Look up PtrAliasMap[R] to see if it maps to a base array region; if so, return that base. Otherwise, just return R.

3. checkPreCall
3.1. Handle copy_from_user
- If !isCopyFromUser(Call): return.
- Extract:
  - DestE = Call.getArgExpr(0)
  - SizeE = Call.getArgExpr(2)
- Determine the array base and size:
  - If getArraySizeForDestExpr(DestE, ArrSz) fails, bail out (we only warn on fixed-size arrays).
  - BaseR = getBaseRegionFromExpr(DestE, C)->getBaseRegion().
- Compute the upper bound of SizeE:
  - UB, Known = getUpperBoundOfSizeArg(SizeE, C).
- Decide safety:
  - Required safety: SizeE ≤ sizeof(array) - 1.
  - Let Limit = ArrSz - 1 (as unsigned APInt).
  - If Known and UB ≤ Limit: safe. Update state: UnboundedCopyMap = UnboundedCopyMap.remove(BaseR) (or set to false).
  - Else (Unknown UB or UB > Limit): unsafe. Update state: UnboundedCopyMap[BaseR] = true. Also, immediately emit a bug:
    - Message: copy_from_user size may exceed destination; cap to min(n, sizeof(buf)-1).
    - Create a non-fatal error node and PathSensitiveBugReport pointing at the call site.
- Note: Even if safe, do not attempt to infer or enforce NUL termination beyond the bound check; the min(size, sizeof-1) check adequately preserves space for NUL.

3.2. Handle string operations
- If isStringOp(Call) is false: return.
- Identify the buffer argument (first argument for these functions): E = Call.getArgExpr(0).
- Resolve to base array region: BaseR = getArrayBaseForArg(E, C).
- Query UnboundedCopyMap[BaseR]:
  - If present and true, emit a bug:
    - Message: String function on buffer after unbounded copy_from_user; missing NUL and overflow risk.
    - Non-fatal error node and PathSensitiveBugReport at the string call.
  - Else: no report.

4. checkBind
- Purpose: track aliases so string functions invoked on pointer variables pointing into fixed-size arrays are recognized.
- When binding a pointer target:
  - If the destination (LHS) is a pointer variable region (call it LHSR).
  - Try to discover if RHS aliases a fixed-size array:
    - If RHS is an Expr, get R = getBaseRegionFromExpr(RHSExpr, C).
      - If R refers to a DeclRefExpr of an array (use findSpecificTypeInChildren<DeclRefExpr> on RHSExpr and getArraySizeFromExpr to confirm), set PtrAliasMap[LHSR] = R->getBaseRegion().
    - Else if RHS is another pointer variable region Rptr and PtrAliasMap[Rptr] exists mapping to BaseR, then set PtrAliasMap[LHSR] = BaseR (alias propagation).
- This tracking enables recognizing p = &buf[0]; followed by strncmp(p, ...).

5. Optional cleanups and scope
- No explicit cleanup is required; maps are per-path and per-function naturally managed by the analyzer.
- You may optionally remove entries from UnboundedCopyMap when you see a subsequent bounded copy_from_user into the same BaseR (as described in 3.1), or when you detect a clear NUL write (e.g., explicit write of ‘0’ to the last byte). For simplicity, the above plan doesn’t require handling explicit NUL writes.

6. Reporting details
- Use std::make_unique<PathSensitiveBugReport> with short, clear messages:
  - For copy_from_user: "copy_from_user size may exceed destination; cap to min(n, sizeof(buf)-1)."
  - For string ops: "String function on buffer after unbounded copy_from_user; missing NUL and overflow risk."
- Use generateNonFatalErrorNode(State) to create the error node for reports.
- Attach the relevant argument expressions as the report range where possible (DestE or the string-argument E).

7. Notes on conservatism and false positives
- We only warn on copy_from_user when the destination is a compile-time constant-sized array and the size upper bound is unknown or greater than sizeof(array)-1.
- We avoid warning when we can prove UB ≤ sizeof(array)-1 using EvaluateExprToInt or inferSymbolMaxVal.
- The string-op warning is secondary and only triggers if an unbounded copy was previously recorded for the same base array region. This keeps the signal focused on the actual bug pattern highlighted by the patch.
