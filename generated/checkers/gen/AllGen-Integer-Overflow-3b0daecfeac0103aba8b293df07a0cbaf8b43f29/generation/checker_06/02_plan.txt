Plan: Detect manual size multiplication passed to kmalloc/kzalloc family (suggest kcalloc/kmalloc_array)

1) Program state
- No custom symbolic reasoning is required for a basic checker.
- Optional precision (recommended, still simple): remember locals that were computed as “count * sizeof(T)” so later calls like kmalloc(sz) are also flagged.
  - REGISTER_MAP_WITH_PROGRAMSTATE(SizeMulMap, const MemRegion *, bool)
    - Key: region of a scalar variable holding a size value.
    - Value: true indicates the variable’s current value is computed as a multiplication by sizeof.

2) Callbacks and implementation steps

A) checkPreCall (main detection point)
- Goal: Catch calls to allocators that take a byte-size as their first argument and where that size is computed by multiplication with sizeof.
- Target functions (exact name match via Call.getCalleeIdentifier()):
  - Zeroing alloc: kzalloc, kvzalloc, devm_kzalloc
  - Non-zeroing alloc: kmalloc, kvmalloc, devm_kmalloc, __kmalloc
- For each targeted call:
  1) Fetch the size argument index:
     - For all targets above, size is argument 0.
  2) Get the Expr* of the size argument and strip parens/imp-casts.
  3) Detect “multiplication by sizeof” directly:
     - If sizeExpr is a BinaryOperator with opcode BO_Mul, then check if either LHS or RHS is a sizeof:
       - sizeof check: dyn_cast<UnaryExprOrTypeTraitExpr>(Op->IgnoreParenImpCasts()) with getKind() == UETT_SizeOf.
       - If one operand is sizeof, record the other as CountExpr (for optional checks).
     - If matched, we have a bug pattern.
  4) If not matched directly, detect via map:
     - If sizeExpr is a DeclRefExpr, get its MemRegion via getMemRegionFromExpr; if region exists in SizeMulMap with true, treat as matched.
  5) Optional noise reduction:
     - If you found a CountExpr in step 3, attempt EvaluateExprToInt on CountExpr. If it succeeds (constant) and is small (e.g., <= 4) you may skip to reduce false positives. Otherwise warn. If evaluation fails (symbolic), warn.
  6) Build a short, clear report:
     - Message: “Use array allocator to avoid overflow: prefer kcalloc/kmalloc_array.”
     - Tailor recommendation based on callee:
       - kzalloc or devm_kzalloc -> suggest kcalloc or devm_kcalloc
       - kmalloc or __kmalloc or devm_kmalloc -> suggest kmalloc_array or devm_kmalloc_array
       - kvmalloc -> suggest kvmalloc_array
       - kvzalloc -> suggest kvcalloc (or kvmalloc_array if kvcalloc not desired/available)
     - Create a non-fatal error node and emit PathSensitiveBugReport.
     - Highlight the size argument range.

B) checkBind (optional precision, simple)
- Goal: Populate SizeMulMap when a variable is assigned a value computed as count * sizeof(T). This catches patterns like:
  - size_t sz = n * sizeof(*p);
  - pa = kzalloc(sz, GFP_KERNEL);
- Implementation:
  1) Only handle bindings where destination is a region of a local or parameter variable (mem region from Loc).
  2) Obtain the Stmt* S from the callback, and try to find the RHS Expr being bound:
     - Using the Stmt* from checkBind, get the RHS via findSpecificTypeInParents<BinaryOperator>(S, C) if needed, or better:
       - If S is a BinaryOperator with opcode BO_Assign, use its RHS.
       - If S is a DeclStmt with an initialized VarDecl, it won’t be seen here; that case is handled in checkPostStmt (below, optional). For checkBind, rely on the analyzer-provided Val’s origin expression: get the ProgramState SVal won’t give the AST, so you should inspect S directly.
  3) If RHS (stripped of parens/imp-casts) is BO_Mul and one side is sizeof (same detection as in A.3), set SizeMulMap[destRegion] = true; otherwise remove any existing entry for destRegion.

C) checkPostStmt(const DeclStmt *) (optional, complements checkBind)
- Goal: Handle declarations with initializers, e.g. “size_t sz = n * sizeof(*p);”
- Implementation:
  1) For each VarDecl in DeclStmt with an initializer:
     - Obtain the initializer Expr, strip parens/imp-casts.
     - If it’s “mul by sizeof” as above, get the region of the variable via getMemRegionFromExpr on a DeclRefExpr constructed by the analyzer for the VarDecl (or use C.getSVal for the initialization site) and set SizeMulMap[region] = true.

D) checkRegionChanges (cleanup, optional)
- When regions are invalidated (e.g., leaving scope), remove them from SizeMulMap to keep state tidy.

3) Helper utilities to implement
- isAllocLike(const CallEvent &Call, StringRef &NameOut):
  - Return true if callee name is one of: {"kmalloc","kzalloc","kvmalloc","kvzalloc","__kmalloc","devm_kmalloc","devm_kzalloc"}; set NameOut.
- getArrayAllocatorSuggestion(StringRef CalleeName):
  - Map:
    - kzalloc -> kcalloc
    - devm_kzalloc -> devm_kcalloc
    - kmalloc, __kmalloc -> kmalloc_array
    - devm_kmalloc -> devm_kmalloc_array
    - kvmalloc -> kvmalloc_array
    - kvzalloc -> kvcalloc (or kvmalloc_array if kvcalloc is not intended; choose kvcalloc if available in your target tree).
- isMulBySizeof(const Expr *E, const Expr *&CountExprOut):
  - Return true if E is a multiplication and one operand is UETT_SizeOf; set CountExprOut to the non-sizeof operand. Ignore parens/imp-casts on both sides.

4) Reporting details
- Use generateNonFatalErrorNode for the bug node.
- Construct a PathSensitiveBugReport with a concise message, suggest the safer API in the text.
- Add the source range of the size argument to the report with addRange.
- One bug per call site.

5) Notes to keep it simple and effective
- This checker does not need complex taint analysis; it flags the universally risky pattern independent of whether the count is user-controlled.
- The optional SizeMulMap improves coverage when the size argument is passed via a temporary variable.
- Keep the pattern match straightforward: binary multiply with a sizeof on either side. This aligns with the real-world kernel pattern the patch fixes.
