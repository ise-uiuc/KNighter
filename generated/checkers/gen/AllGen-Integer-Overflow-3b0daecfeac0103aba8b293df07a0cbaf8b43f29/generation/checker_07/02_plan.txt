1) Program state
- No custom program state is necessary. This is a syntactic/semantic pattern check on call arguments. We only need to inspect function calls and the size argument’s AST.

2) Callbacks to use
- checkPreCall: Inspect calls to allocation APIs and analyze the size argument to detect manual size multiplications.
- (No other callbacks are required.)

3) Detailed implementation steps

A. Define a small, static table of allocation APIs to check
- Create a table mapping function names to:
  - The index of the size argument.
  - The recommended alternative function name (for a succinct diagnostic).
- Suggested entries:
  - {"kmalloc", 0, "kcalloc or kmalloc_array"}
  - {"kzalloc", 0, "kcalloc"}
  - {"__kmalloc", 0, "kcalloc or kmalloc_array"}
  - {"kvmalloc", 0, "kcalloc or kmalloc_array"}
  - {"kvzalloc", 0, "kcalloc"}
  - {"devm_kmalloc", 1, "devm_kcalloc or kmalloc_array"}
  - {"devm_kzalloc", 1, "devm_kcalloc"}
  - Optionally add others where the “size” parameter is first or known (e.g., dma_alloc_coherent is not relevant here).

B. Helper routines (local to the checker)
- strip(E): return E->IgnoreParenImpCasts().
- flattenMulFactors(E, OutVec):
  - Recursively flatten a multiplicative expression: if E is a BinaryOperator with opcode BO_Mul, call flattenMulFactors on LHS and RHS; otherwise push_back(E).
- hasSizeofFactor(Factors):
  - Return true if any factor is a UnaryExprOrTypeTraitExpr with UETT_SizeOf.
- containsSafeMacro(E, C):
  - Use ExprHasName(E, "struct_size", C) or ExprHasName(E, "array_size", C) or ExprHasName(E, "size_mul", C) to optionally suppress well-known overflow-guarded macro patterns. Keep this small and conservative.
- isManualArraySizeExpr(E, C):
  - E = strip(E).
  - If E is not a BinaryOperator(BO_Mul) (after stripping), return false.
  - Build a vector<const Expr*> Factors via flattenMulFactors(E).
  - If hasSizeofFactor(Factors) and Factors.size() >= 2, return true; else false.
  - Optionally: if containsSafeMacro(E, C) return false (suppression).

C. checkPreCall implementation
- Extract callee identifier: if no identifier, return.
- Look up in the allocation table. If not found, return.
- Retrieve the size argument expression via the recorded index.
- If isManualArraySizeExpr(SizeArg, C) is true:
  - Prepare a short diagnostic message. Use the table’s recommended alternative:
    - Example: For kzalloc/kmalloc variants: "Use kcalloc() for array allocation; multiplication may overflow"
    - For devm_kmalloc/kzalloc: "Use devm_kcalloc() for array allocation; multiplication may overflow"
    - You can also mention “or kmalloc_array()” when appropriate.
  - Create a non-fatal error node and emit a BasicBugReport or PathSensitiveBugReport:
    - BugType: "Array allocation via kmalloc/kzalloc may overflow"
    - Message (short and clear): "Use kcalloc() for array allocations; manual size multiplication can overflow"
    - Add the size argument source range to the report.
- Do nothing if not matched or suppressed.

D. Notes and rationale
- We warn whenever the size parameter is formed by multiplying sizeof(...) with a count expression. This directly captures the unsafe idiom pa = kzalloc(sizeof(struct elem) * n, GFP_KERNEL).
- We intentionally avoid complex flow analysis (no program state). This keeps the checker simple and robust.
- Minimal suppression is included to reduce noise for common safe macros (struct_size/array_size/size_mul). Keep the suppression conservative and string-based via ExprHasName.

4) Reporting
- Use generateNonFatalErrorNode and emit a concise report via:
  - std::make_unique<BasicBugReport>(BugType, Message, Location)
  - Or PathSensitiveBugReport if you prefer path integration.
- Example messages:
  - "Use kcalloc() for array allocations; manual size multiplication can overflow"
  - For devm_*: "Use devm_kcalloc() for array allocations; manual size multiplication can overflow"

5) Summary of the minimal checker flow
- In checkPreCall:
  - If callee in {kmalloc, kzalloc, kvmalloc, kvzalloc, __kmalloc, devm_kmalloc, devm_kzalloc}
  - Identify the size parameter by index.
  - If it is a multiplication chain containing sizeof(...), and not within a known safe macro:
    - Report the issue, recommending kcalloc (or devm_kcalloc / kmalloc_array).
