Plan

1. Program state
- No custom program state is needed. This checker is a local syntactic/semantic pattern match on allocator calls.

2. Callback selection
- Use checkPreCall as the single entry point. We only need to inspect the allocator calls’ arguments before evaluating the call.

3. Detect target allocators and their size-argument index
- In checkPreCall:
  - Identify calls to allocators that accept a single “total size” parameter and are commonly used to allocate arrays:
    - kmalloc(size, gfp)  -> size index 0
    - kzalloc(size, gfp)  -> size index 0
    - kvmalloc(size, gfp) -> size index 0
    - kvzalloc(size, gfp) -> size index 0
    - devm_kmalloc(dev, size, gfp)  -> size index 1
    - devm_kzalloc(dev, size, gfp)  -> size index 1
    - vzalloc(size) -> size index 0
  - Ignore calls that already use array-aware APIs (do not warn):
    - kcalloc, kvcalloc, kmalloc_array, kvmalloc_array, devm_kcalloc
  - Implement a small helper getAllocatorSizeArgIndex(const CallEvent &Call, unsigned &Idx) returning true if the callee is one of the above and setting Idx; return false otherwise.
  - If not a target allocator, return.

4. Decide if the size argument is a risky “count * sizeof” multiplication
- Fetch the size expression E = Call.getArgExpr(SizeIdx).
- Quickly filter out safe size-building helpers using source text:
  - If ExprHasName(E, "array_size", C) or ExprHasName(E, "struct_size", C) or ExprHasName(E, "flex_array_size", C), return (these helpers include overflow checks).
- Strip implicit casts and parentheses: E = E->IgnoreParenImpCasts().
- Identify multiplication:
  - If E is a BinaryOperator with opcode BO_Mul, proceed; else return.
  - Let BO = cast<BinaryOperator>(E). For BO->getLHS() and BO->getRHS():
    - Determine if either subtree contains a sizeof expression:
      - Use findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(SideExpr) and check UETT->getKind() == UETT_SizeOf.
    - If neither side contains sizeof, return (we only warn for count * sizeof(...) forms).
- Optional refinement (keep simple):
  - Do not attempt to evaluate constants or prove overflow; this checker flags the risky pattern, not concrete overflow.

5. Report the issue
- If the pattern is found, emit a warning before the call executes:
  - Create a non-fatal error node with generateNonFatalErrorNode().
  - Use a PathSensitiveBugReport (or BasicBugReport) with a concise message, e.g.:
    - "Prefer kcalloc(count, size, ...) over count*sizeof in kmalloc/kzalloc to avoid overflow."
  - Highlight the multiplication expression’s source range (the BinaryOperator E).
  - Only one report per call site.

6. Implementation details and utilities usage
- Utilities:
  - findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr> to detect sizeof anywhere under an operand.
  - ExprHasName(E, "array_size", C) and similar to suppress false positives where overflow-checked helpers are used.
- Robustness:
  - Handle implicit casts and parentheses via IgnoreParenImpCasts().
  - Accept both operand orders: sizeof(...) * count and count * sizeof(...).
  - The same logic applies to kmalloc/kzalloc and their devm_*/kv*/vzalloc variants listed above; size argument index differs for devm_*.

7. Scope and limitations
- This checker warns on the risky pattern regardless of whether overflow is provably possible on a given path. The goal is API misuse (prefer kcalloc/kmalloc_array/kvcalloc).
- Suppression: If the size expression already uses array_size/struct_size/flex_array_size helpers, do not warn.
