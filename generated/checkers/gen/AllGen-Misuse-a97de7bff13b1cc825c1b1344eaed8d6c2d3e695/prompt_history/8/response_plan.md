1) Program state
- No custom program state is required. We will leverage the analyzer’s existing path constraints and assume machinery to check whether the current path guarantees optlen is large enough.

2) Callbacks and implementation

- checkPreCall
  Goal: Detect unsafe copies from sockptr in setsockopt handlers where optlen is not validated against the destination size, and detect partial-copy patterns (min or passing optlen directly).

  Steps:
  1. Identify target calls:
     - Only act on calls whose callee identifier is one of:
       - "copy_from_sockptr"
       - "copy_from_sockptr_offset"
     - Ignore "bt_copy_from_sockptr" (it is the correct helper).
  2. Restrict the context to setsockopt-like functions:
     - Get the current FunctionDecl from C.getLocationContext()->getDecl().
     - Return early unless:
       - The function name contains "setsockopt" (case-sensitive substring match), and
       - It has a parameter named "optlen" of integer type, and a parameter named "optval" (usually sockptr_t). Prefer exact name matches via Param->getNameAsString() == "optlen"/"optval" for robustness in the kernel style.
     - Record the VarDecl* for the "optlen" parameter. We’ll use it to fetch its SVal.
  3. Extract the length argument:
     - For copy_from_sockptr, the length is argument index 2 (dst, optval, len).
     - For copy_from_sockptr_offset, the length is argument index 3 (dst, optval, offset, len).
     - Obtain const Expr *LenE = Call.getArgExpr(IdxLen).
  4. Flag partial-copy pattern immediately:
     - If ExprHasName(LenE, "optlen", C) returns true (length expression mentions optlen), report a bug:
       - Message: "setsockopt copies partial user buffer; reject short optlen"
       - Rationale: Passing optlen straight (or via min() macros) permits partial copies, which is forbidden; the correct approach is to require optlen to be at least the expected size and copy that size.
     - Do not proceed further for this call path (we already reported).
  5. If not partial-copy, try to resolve a constant expected size:
     - Attempt EvaluateExprToInt on LenE. If it succeeds, let K be the resulting integer (APSInt -> uint64_t).
       - Typical examples: sizeof(u32), sizeof(*dst), sizeof(struct xyz), etc.
     - If EvaluateExprToInt fails, return without a report (we keep the checker simple and only reason about known constant sizes).
  6. Check that the current path guarantees optlen >= K:
     - Fetch SVal of the "optlen" parameter: SVal OptlenSV = State->getSVal(DeclRefExpr constructed from the VarDecl, LCtx). Convert it to NonLoc as needed.
     - Build a NonLoc constant for K using SValBuilder (e.g., makeIntVal(K, OptlenType)).
     - Build a comparison NonLoc CondGE = (optlen >= K) via SValBuilder.evalBinOpNN.
     - Query feasibility using ProgramStateRef:
       - STrue = State->assume(CondGE, true)
       - SFalse = State->assume(CondGE, false)
       - If SFalse is null, then CondGE is definitely true on this path ⇒ SAFE, do nothing.
       - Otherwise (STrue non-null and SFalse non-null, or STrue null), it is not guaranteed that optlen >= K on this path ⇒ report a bug:
         - Message: "copy_from_sockptr without validating optlen"
  7. Reporting:
     - Use generateNonFatalErrorNode to get a node.
     - Use std::make_unique<PathSensitiveBugReport> with a concise message (as above).
     - Attach LenE as the interesting location.

- No other callbacks are strictly necessary.

3) Notes and heuristics

- Why checkPreCall is enough:
  - The analyzer already maintains path constraints, so our assume-based check will honor prior guards such as:
    - if (optlen < sizeof(sec)) return -EINVAL;
    - if (optlen >= sizeof(u32)) { copy_from_sockptr(..., sizeof(u32)); }
  - If those checks are present and effective, the optlen >= K assumption will be provably true on the path that reaches the call, and we won’t warn.

- What we flag:
  - Calls to copy_from_sockptr/copy_from_sockptr_offset inside a setsockopt handler that:
    - Pass a constant size K but are not provably guarded with optlen >= K on the current path.
    - Pass any length expression that mentions "optlen" (e.g., min_t(..., sizeof(*dst), optlen) or simply optlen).
  - We do not flag calls to bt_copy_from_sockptr.

- Utility functions to use:
  - ExprHasName to quickly detect "optlen" presence in the length expression.
  - EvaluateExprToInt to extract K from sizeof(...) and integer constants.

- Reduction of false positives:
  - Limit to functions whose name contains "setsockopt" and that have parameters named "optval" and "optlen".
  - Require the length expression to be either:
    - A constant (so we can verify via assume), or
    - An expression that explicitly involves "optlen" (which we treat as a bug because it permits partial copies).
  - Exclude bt_copy_from_sockptr calls.

- Messages:
  - For missing validation: "copy_from_sockptr without validating optlen"
  - For partial copies: "setsockopt copies partial user buffer; reject short optlen"
