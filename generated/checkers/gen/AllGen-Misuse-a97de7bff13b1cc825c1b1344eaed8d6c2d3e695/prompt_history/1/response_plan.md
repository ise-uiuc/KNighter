Plan to detect unsafe copy_from_sockptr usage in setsockopt handlers

1) Program state
- Keep it minimal. Use a single set to remember size variables computed via min(optlen, ...):
  - REGISTER_SET_WITH_PROGRAMSTATE(MinLenVars, const MemRegion *)
  - Purpose: if code does len = min_t(..., optlen); then later uses len as size for copy_from_sockptr, we can flag it even if the call passes a plain variable.

2) Chosen callbacks and how to implement them

A) checkPostCall (main detection)
- Goal: Flag calls that copy fixed-size values/structs from optval without validating optlen, and flag min-based partial copies.
- Steps:
  1. Identify relevant calls:
     - If callee name is bt_copy_from_sockptr: return (safe helper; do not warn).
     - If callee name is copy_from_sockptr or copy_from_sockptr_offset: proceed.
     - Otherwise ignore.
  2. Ensure we are in a setsockopt-like handler to reduce false positives:
     - Retrieve the current FunctionDecl via C.getLocationContext()->getDecl().
     - Consider it a handler if:
       - The function name contains "setsockopt" (case-sensitive), or
       - It has parameters: one of type sockptr_t (optval) and one unsigned int/size_t param whose name contains "optlen".
     - If neither condition holds, ignore the call.
  3. Locate the arguments:
     - For copy_from_sockptr(dst, src, size): size is arg index 2.
     - For copy_from_sockptr_offset(dst, src, offset, size): size is arg index 3.
     - Keep a pointer to the size Expr SzArg and the destination Expr DstArg (arg index 0).
  4. Detect “min with optlen” pattern (partial copy bug):
     - If ExprHasName(SzArg, "min") or ExprHasName(SzArg, "min_t"), and also ExprHasName(SzArg, "optlen"), immediately report: "length uses min(optlen, ...); may leave fields uninitialized".
     - Else if SzArg is a DeclRefExpr referring to a variable whose region is in MinLenVars, report the same message.
  5. Detect “no optlen validation” with fixed-size copy:
     - If SzArg does not mention "optlen" (ExprHasName(SzArg, "optlen") is false), proceed to check if it is a fixed size:
       - Try EvaluateExprToInt(SzVal, SzArg, C). If constant and > 0, consider it a fixed length.
       - Else, if SzArg is a sizeof-like expression (UnaryExprOrTypeTraitExpr), treat it as fixed length.
       - Optional refinement: try to compute sizeof(DstArg)’s pointee type via ASTContext if DstArg is &var; treat as fixed length.
     - If fixed length and the call is not bt_copy_from_sockptr, report: "copy_from_sockptr without validating optlen >= size; use bt_copy_from_sockptr".
  6. Bug report:
     - Use generateNonFatalErrorNode and a PathSensitiveBugReport.
     - Keep messages short:
       - For min-case: "Partial copy from optval via min(optlen, ...); uninitialized fields possible."
       - For fixed-size no-check: "copy_from_sockptr lacks optlen >= size check; use bt_copy_from_sockptr."

B) checkBind (track variables computed via min(optlen, ...))
- Goal: If the size expression is assigned to a temporary (e.g., len = min_t(..., optlen)), remember that variable as “min-derived”.
- Steps:
  1. Only process bindings where both Loc and Val are non-null and S is an assignment.
  2. Get the bound region for the LHS via getMemRegionFromExpr.
  3. Inspect the RHS (Val’s originating Expr; use findSpecificTypeInParents<const BinaryOperator> or the S as needed):
     - If the RHS expression contains "min" or "min_t" (ExprHasName), and also contains "optlen", add the LHS MemRegion to MinLenVars.
  4. Do not remove from the set unless that variable is reassigned with a non-min RHS; if you want, you can clear the mark on a rebind when RHS no longer has min/optlen.

C) Optional minor refinements (keep simple)
- You can also catch direct calls where SzArg itself is optlen: these are safe; do not warn.
- If callee is memcpy and src is optval.ptr (rare with sockptr), ignore to reduce noise.

3) Heuristics and helper logic

- Recognizing setsockopt handlers:
  - By name: FunctionDecl->getNameAsString().contains("setsockopt").
  - By signature: presence of a sockptr_t parameter and an unsigned int/size_t parameter named with "optlen".
- Finding optlen or optval mentions in expressions:
  - Use ExprHasName(E, "optlen") and ExprHasName(E, "min") / "min_t".
  - If stronger matching is needed, scan children for DeclRefExpr to a ParamVarDecl whose name contains "optlen".
- Distinguishing safe helper:
  - Any call to bt_copy_from_sockptr(...) should be treated as safe and not reported.

4) What this detects
- Copying a fixed-size amount (e.g., sizeof(u32), sizeof(struct)) from optval with copy_from_sockptr in a setsockopt handler without using bt_copy_from_sockptr and without referencing optlen in the size argument. This matches the rfcomm_sock_setsockopt_old bug.
- Using min(optlen, sizeof(...)) to compute size for copy_from_sockptr (either directly as the call arg or indirectly through a temporary). This matches the rfcomm_sock_setsockopt bug where min_t was used, potentially leaving part of the struct uninitialized.

5) What it intentionally avoids (to stay simple and reduce false positives)
- No path-sensitive reasoning to prove an earlier if (optlen < sizeof(...)) return; guard. This may cause occasional false positives; keeping messages actionable and specific helps.
- No alias tracking for optlen beyond direct name match; kernel code conventionally uses the name "optlen".

6) Reporting
- Use std::make_unique<PathSensitiveBugReport>.
- Keep messages short:
  - "copy_from_sockptr lacks optlen >= size check; use bt_copy_from_sockptr"
  - "Partial copy from optval via min(optlen, ...); uninitialized fields possible"
- Anchor the report at the risky call expression.
