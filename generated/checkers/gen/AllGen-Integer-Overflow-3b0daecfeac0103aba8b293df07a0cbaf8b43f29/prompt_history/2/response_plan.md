Plan

1. Program state
- No custom program state is necessary. This checker is purely syntactic/semantic on the call expression and its size argument.

2. Callback functions
- Use only checkPreCall. It is sufficient to:
  - Identify calls to kmalloc/kzalloc-like allocators that take a single size parameter.
  - Inspect the size argument’s AST for a “sizeof(.) * count” (or count * sizeof(.)) multiplication pattern.
  - Suppress the report if the “count” side is a compile-time constant.
  - Emit a concise warning suggesting kcalloc.

3. Targets and matching
- Functions to flag:
  - kmalloc(size, gfp)
  - kzalloc(size, gfp)
  - __kmalloc(size, gfp)
  - kmalloc_node(size, gfp, node)
  - kzalloc_node(size, gfp, node)
- Ignore already-safe APIs: kcalloc, kmalloc_array, kvmalloc_array, kvcalloc, struct_size, array_size, etc. We only match the above “one size argument” kmalloc-like functions.

4. checkPreCall implementation
- Step A: Identify target allocator
  - Get the callee name with Call.getCalleeIdentifier()->getName().
  - If not in {"kmalloc", "kzalloc", "__kmalloc", "kmalloc_node", "kzalloc_node"}, return.
- Step B: Obtain the size expression
  - For all matched functions, the first argument (index 0) is the size.
  - Expr *SizeArg = Call.getArgExpr(0)->IgnoreParenImpCasts().
- Step C: Detect “sizeof * count” pattern
  - Define a small helper: bool isMulOfSizeof(const Expr *E, const Expr *&CountExpr, const Expr *&SizeofExpr).
    - If E is a BinaryOperator with opcode BO_Mul:
      - Let L = LHS->IgnoreParenImpCasts(), R = RHS->IgnoreParenImpCasts().
      - If L is a UnaryExprOrTypeTraitExpr of kind UETT_SizeOf, then CountExpr = R and SizeofExpr = L, return true.
      - Else if R is UETT_SizeOf, then CountExpr = L and SizeofExpr = R, return true.
    - Otherwise, try to find a multiplication deeper in the tree:
      - Use findSpecificTypeInChildren<BinaryOperator>(E) to get a sub-multiplication (if any) and apply the above “L/R” logic. If none, return false.
- Step D: Suppress obvious constants
  - If isMulOfSizeof(SizeArg, CountExpr, SizeofExpr) is false, return.
  - Try to evaluate CountExpr to a constant with EvaluateExprToInt(..., CountExpr, C).
    - If true (constant), do not warn to avoid noisy false positives for fixed-size arrays.
- Step E: Emit the report
  - Create a BugType once (e.g., “kmalloc/kzalloc array allocation overflow risk”).
  - Use C.generateNonFatalErrorNode() to get an error node.
  - Emit a PathSensitiveBugReport (or BasicBugReport) with a short message, e.g.:
    - “kmalloc/kzalloc size uses count * element size; use kcalloc(count, elem_size, ...) to avoid overflow.”
  - Optionally, add source ranges:
    - Highlight the SizeArg range.
    - If available, also highlight CountExpr and SizeofExpr subranges for clarity.

5. Helper details
- isMulOfSizeof:
  - Prefer checking the top-level BinaryOperator first (fast path).
  - If not a BinaryOperator at the top, use findSpecificTypeInChildren<BinaryOperator> to find a multiplication somewhere in the size expression (to catch cases like casts and parenthesized expressions).
  - Accept both sizeof(type) and sizeof(expr) via UnaryExprOrTypeTraitExpr (UETT_SizeOf).
- Constant suppression:
  - Use the provided EvaluateExprToInt to filter out expressions that evaluate to a compile-time integer. If EvaluateExprToInt returns true, skip reporting.
- False-positive control (kept simple on purpose):
  - Do not attempt to track pre-call overflow guards (e.g., “if (n > ULONG_MAX / sizeof(T)) ...”). Keeping the checker simple and focused: it warns on non-constant count multiplications and suggests kcalloc. This matches the typical kernel recommendation and the provided patch.

6. Notes/edges the checker will handle
- Handles both n * sizeof(T) and sizeof(T) * n (either operand).
- Handles implicit/explicit casts and parentheses around operands via IgnoreParenImpCasts.
- Will not warn on direct calls to kcalloc/kmalloc_array/kvcalloc/kvmalloc_array/etc.
- Keeps noise low by suppressing constant-count patterns.

7. Reporting
- One concise message per detected call site:
  - Title: “Array allocation with kmalloc/kzalloc may overflow”
  - Message: “kmalloc/kzalloc size uses count * element size; use kcalloc(count, elem_size, ...) to avoid overflow.”
- Use std::make_unique<PathSensitiveBugReport> on the created node and C.emitReport.
