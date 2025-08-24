1) Program state
- No custom program states are needed. This checker is a syntactic/semantic pattern match at call sites, with an optional lightweight constraint query to reduce false positives.

2) Callback functions and implementation steps

A. checkPreCall
- Goal: Detect calls to kmalloc/kzalloc (and close variants) where the size argument is a product n * sizeof(T) (or sizeof(T) * n), which is overflow-prone. Recommend using kcalloc/kmalloc_array instead.

- Recognize target allocation functions:
  - Match callee names (exact string match of IdentifierInfo):
    - kmalloc, kzalloc
    - kmalloc_node, kzalloc_node
    - kvmalloc, kvzalloc (optional, if present in the code base)
  - For all of these, the “size” parameter is the first argument (index 0).

- Extract and normalize the “size” argument:
  - Retrieve Arg0 = Call.getArgExpr(0).
  - Strip parens and implicit casts: Arg0 = Arg0->IgnoreParenImpCasts().

- Identify the risky multiplication pattern:
  - If Arg0 is not a BinaryOperator with opcode BO_Mul, return (no issue).
  - Let LHS = BO->getLHS()->IgnoreParenImpCasts() and RHS = BO->getRHS()->IgnoreParenImpCasts().
  - Determine which side is a sizeof:
    - Check if LHS or RHS is a UnaryExprOrTypeTraitExpr of kind UETT_SizeOf.
    - If neither side is sizeof, return (to keep false positives low).
  - Determine if this is a likely variable-length allocation, not a compile-time constant:
    - If both operands evaluate to constants (use EvaluateExprToInt on LHS and RHS), then skip.
    - Otherwise, continue.

- Optional false positive reduction by simple range reasoning:
  - Identify the count operand CountExpr = (the non-sizeof operand).
  - Try to get element size:
    - If the sizeof operand is present, EvaluateExprToInt on that operand to obtain ElemSize (APSInt). If evaluation fails (shouldn’t for sizeof), skip the range check.
  - Try to infer the maximum possible value for CountExpr:
    - Get SymbolRef SymCount = C.getSVal(CountExpr).getAsSymbol().
    - If SymCount exists, query const llvm::APSInt* CountMax = inferSymbolMaxVal(SymCount, C).
    - If CountMax is non-null and ElemSize is known:
      - Compute MaxSizeT = all-ones for size_t (obtain width from ASTContext for size_t, create an APSInt with that bitwidth with all bits set).
      - Compute SafeLimit = floor(MaxSizeT / ElemSize). If CountMax <= SafeLimit, then along this path the multiplication cannot overflow; skip reporting to avoid noise.
  - If no symbol or no bounds are available, proceed with reporting (better be conservative).

- Report:
  - If the risky pattern is found and not suppressed, emit a diagnostic.
  - Create an error node with generateNonFatalErrorNode.
  - Use PathSensitiveBugReport with a short message:
    - “Multiplying count and element size in kmalloc/kzalloc may overflow; use kcalloc/kmalloc_array.”
  - Attach the report range to the multiplication expression (the BinaryOperator) or the first argument of the call for clarity.

B. (No other callbacks needed)
- No need for checkPostCall, checkBind, checkLocation, or branch handling for this checker.
- The optional range reasoning is already handled inside checkPreCall via inferSymbolMaxVal.

3) Notes and heuristics
- Functions to match and their argument indices:
  - kmalloc(size, flags), kzalloc(size, flags): check Arg0
  - kmalloc_node(size, flags, node), kzalloc_node(size, flags, node): check Arg0
  - kvmalloc(size, flags), kvzalloc(size, flags): check Arg0 (optional)
- Size expression patterns to accept:
  - sizeof(T) * n, n * sizeof(T), sizeof(*p) * n, sizeof(p[0]) * n
- Skip when:
  - The size argument is not a multiplication.
  - Neither side of the multiplication is a sizeof expression.
  - Both sides are constants (no variability).
  - Optional: Proven safe bound (CountMax <= MaxSizeT / ElemSize).
- This checker intentionally does not attempt to detect prior manual overflow checks in source code conditionals. Instead, it relies on the optional path constraint-based upper bound to minimize false positives. The recommendation remains to use kcalloc/kmalloc_array for built-in overflow checking.
