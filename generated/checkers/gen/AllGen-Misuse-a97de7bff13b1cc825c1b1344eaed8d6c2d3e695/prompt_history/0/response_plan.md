1) Program state

- Keep it minimal, but track path-sensitive bounds learned for the specific parameter optlen:
  - REGISTER_MAP_WITH_PROGRAMSTATE(OptlenLowerBoundMap, const MemRegion*, llvm::APSInt)
    - Key: MemRegion of the ParmVarDecl named "optlen".
    - Value: The best-known lower bound (>=) for optlen along the current path.
  - Rationale: This lets us suppress false positives when the code already checked optlen >= expected_size in the current branch.

2) Core idea and targets

- Target calls that copy from sockptr_t inside setsockopt handlers using a fixed size not validated against optlen:
  - copy_from_sockptr(void *dst, sockptr_t src, size_t size) — size at arg index 2.
  - copy_from_sockptr_offset(void *dst, sockptr_t src, size_t offset, size_t size) — size at arg index 3.
- Restrict to functions that:
  - Have a name containing "setsockopt".
  - Have a parameter named "optlen".
  - Also have a parameter named "optval" (heuristic to ensure we’re matching setsockopt-like handlers).
- Do not warn if the safe helper is used: bt_copy_from_sockptr(&dst, sizeof(dst), optval, optlen).
- Do not warn if the size expression of copy_from_sockptr refers to optlen (e.g., min(optlen, ...), or directly optlen), since that implies a length-aware read.
- Warn when a fixed constant size (e.g., sizeof(u32) or integer literal) is passed and there is no path constraint ensuring optlen >= that size.

3) Helper utilities to implement

- isSetSockoptHandler(const FunctionDecl *FD):
  - Return true if FD->getNameAsString() contains "setsockopt".
  - Additionally, ensure it has parameters named "optlen" and "optval".
- getOptlenParm(const FunctionDecl *FD) -> const ParmVarDecl*:
  - Return the ParmVarDecl whose name is exactly "optlen" and is of integer type.
- isSockptrCopyCall(const CallEvent &Call, unsigned &SizeArgIndex):
  - If callee name is "copy_from_sockptr", set SizeArgIndex = 2 and return true.
  - If "copy_from_sockptr_offset", set SizeArgIndex = 3 and return true.
  - If "bt_copy_from_sockptr", return false (explicitly do not warn).
- getConstSizeValue(const Expr *E, CheckerContext &C, llvm::APSInt &Out):
  - Use EvaluateExprToInt to resolve constants and sizeof-expressions.
- sizeExprMentionsOptlen(const Expr *E, CheckerContext &C):
  - Return true if ExprHasName(E, "optlen", C) is true (the size depends on optlen).
- getParmRegion(const ParmVarDecl *PVD, CheckerContext &C) -> const MemRegion*:
  - Build a DeclRefExpr from PVD or obtain its region via C.getState()->getLValue(PVD, C.getLocationContext()).getAsRegion().
  - (It’s acceptable to leverage getMemRegionFromExpr if you construct a DRE; otherwise, use the store manager to get the LValue region directly.)
- updateLowerBound(ProgramStateRef St, const MemRegion *OptlenMR, const llvm::APSInt &NewLB) -> ProgramStateRef:
  - Read prior LB from OptlenLowerBoundMap; write back max(prior, NewLB).

4) Callbacks and their roles

- checkBeginFunction(CheckerContext &C):
  - If current function is not a setsockopt handler (isSetSockoptHandler == false), do nothing.
  - If true, initialize state for this function:
    - Identify the "optlen" parameter (getOptlenParm), get its MemRegion, and ensure any old entry for it is removed from OptlenLowerBoundMap.
  - No transitions necessary aside from storing the cleared state (if modified).

- checkBranchCondition(const Stmt *Condition, CheckerContext &C):
  - Only if we are in a setsockopt handler and we can find an "optlen" parameter region.
  - Extract the condition expression (e.g., BinaryOperator).
  - Handle comparisons where one side mentions optlen and the other side is an integer constant or sizeof-expression (resolved via getConstSizeValue). Support:
    - optlen >= K or K <= optlen -> true branch LB := max(LB, K)
    - optlen > K -> true branch LB := max(LB, K+1)
    - optlen < K -> false branch LB := max(LB, K)
    - optlen <= K -> false branch LB := max(LB, K+1)
  - Use C.getState()->assume(Cond) to split into StTrue/StFalse and add transitions:
    - On StTrue, update LB for the true-branch rule above.
    - On StFalse, update LB for the false-branch rule above.
  - If the condition does not reference optlen or we cannot resolve K, do nothing.

- checkPostCall(const CallEvent &Call, CheckerContext &C):
  - If callee is bt_copy_from_sockptr, return (safe path).
  - If not a sockptr copy call (isSockptrCopyCall == false), return.
  - If current function context is not a setsockopt handler, return.
  - Determine size argument index (SizeArgIndex).
  - Obtain the size expression: const Expr *SizeE = Call.getArgExpr(SizeArgIndex).
  - If sizeExprMentionsOptlen(SizeE, C) is true, return (length-aware use; don’t warn).
  - Try getConstSizeValue(SizeE, C, ConstSize). If fails, return (we only target fixed-size reads).
  - Find the "optlen" parameter and its MemRegion.
  - Check OptlenLowerBoundMap for this region:
    - If present and LowerBound >= ConstSize, return (properly validated on this path).
    - Else, warn.
  - Reporting:
    - Create a non-fatal error node and emit a PathSensitiveBugReport with message like:
      "copy_from_sockptr uses fixed size without ensuring optlen is large enough"
    - Optionally add a note range at the size argument to highlight the fixed-size value.

5) Optional minor suppressions (simple heuristics)

- If the nearest enclosing IfStmt (use findSpecificTypeInParents<IfStmt>(CallExpr)) has a condition that mentions "optlen" and contains ">=" or ">= sizeof", and the then-branch contains the call, you may skip the warning. This is optional; the path-sensitive LB map should already handle typical cases.

6) Summary of detection logic

- Trigger only inside setsockopt handlers (name contains "setsockopt" and parameters include "optval" and "optlen").
- Target calls to copy_from_sockptr(_offset) using a fixed size argument that does not reference optlen.
- Use a simple path-sensitive lower-bound map updated by branch conditions to see if the current path guarantees optlen >= that fixed size.
- If no such guarantee, report a bug.

7) Chosen callbacks

- checkBeginFunction: initialize optlen tracking for the function.
- checkBranchCondition: update OptlenLowerBoundMap when conditions constrain optlen.
- checkPostCall: detect unsafe copy_from_sockptr usage, consult the lower bound map, and report.
- No other callbacks are necessary.
