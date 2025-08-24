Plan

1) Program state
- No custom program state is necessary. This checker is a pattern detector on call sites.

2) Callbacks
- Use checkPostCall as the single entry point to detect the pattern. No alias or path reasoning is required.

3) Detection logic in checkPostCall
- Identify relevant allocator functions:
  - Bad (scalar) allocators taking a single size expression: kmalloc, kzalloc, kvzalloc, kmalloc_node, kzalloc_node, devm_kmalloc, devm_kzalloc.
  - Exclude array allocators: kcalloc, kmalloc_array, kvcalloc, devm_kcalloc (never warn for these).
- For calls to the bad allocators:
  - Determine the index of the size argument:
    - For all listed bad allocators, the size argument is arg[0].
  - Extract the size expression: const Expr *SizeE = Call.getArgExpr(0)->IgnoreParenImpCasts().
  - Find a multiplication in the size expression:
    - Use findSpecificTypeInChildren<BinaryOperator>(SizeE).
    - If a BinaryOperator is found, require BO_Mul (ignore other ops).
    - If not found at the top level, repeat once more by calling findSpecificTypeInChildren starting from SizeE to find any descendant BinaryOperator and ensure it is BO_Mul.
    - If no multiplication is found, do not warn.
  - Check that the multiplication involves a sizeof:
    - On the found multiplication expression M (BinaryOperator '*'), inspect both operands (LHS, RHS). For each:
      - Use findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(operand) and confirm Kind == UETT_SizeOf.
      - Alternatively, as a fallback, use ExprHasName(operand, "sizeof", C).
    - If neither side contains a sizeof subtree, do not warn.
  - Optional suppression for obvious constant-safe sizes:
    - If EvaluateExprToInt(EvalRes, SizeE, C) returns true (i.e., a compile-time constant), do not warn.
  - Optional suppression using symbolic max bounds (reduce noise):
    - If exactly one side contains sizeof(T) and the other side is a DeclRefExpr (or reduces to a symbol):
      - Extract sizeof(T) as an integer:
        - The sizeof AST is a UnaryExprOrTypeTraitExpr. Get its argument’s type, then compute element size in bytes using C.getASTContext().getTypeSizeInChars(QT).getQuantity() (or evaluate the sizeof expr directly via EvaluateExprToInt).
      - Obtain the symbol for the count side via ProgramState SVal lookup or from Call.getArgSVal(0) subtree; if you can get SymbolRef CountSym, then:
        - Use inferSymbolMaxVal(CountSym, C) to get a max bound.
        - Compute limit = SIZE_MAX / elem_size (use ASTContext.getTypeSize(C.getASTContext().getSizeType()) to get size_t width and build an APSInt of all-ones).
        - If maxVal <= limit, skip reporting; otherwise, continue to warn.
    - If any of the above steps fail, proceed with warning (conservative).
  - Emit a report:
    - Create a BugType once (e.g., "Potential overflow in size calculation for kmalloc/kzalloc").
    - Generate a non-fatal error node and emit a PathSensitiveBugReport at the call expression.
    - Short message: "Size uses sizeof(...) * count in kmalloc/kzalloc; use kcalloc/kmalloc_array to avoid overflow."
    - Point the primary location to the size argument (SizeE) if available.
    - Optionally, add a note with the function name to guide remediation: "Replace with kcalloc(count, sizeof(elem), ...)."

4) Helper details
- Function filtering:
  - Implement a small helper isScalarAllocator(const CallEvent &Call) that matches callee names from a small set:
    - {"kmalloc", "kzalloc", "kvzalloc", "kmalloc_node", "kzalloc_node", "devm_kmalloc", "devm_kzalloc"}.
  - Implement isArrayAllocator similarly ({"kcalloc", "kmalloc_array", "kvcalloc", "devm_kcalloc"}) and early-return if true.
- Size argument retrieval:
  - For all targeted scalar allocators, the size expression is argument 0; ignore parens/implicit casts.
- Finding sizeof:
  - Use findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr> to detect sizeof anywhere under an operand.
- Constant evaluation:
  - Use EvaluateExprToInt on the full SizeE to drop compile-time-constant sizes.
- Symbolic maximum (optional noise reduction):
  - If the non-sizeof multiplicand is a simple DeclRefExpr or resolves to a symbolic SVal, attempt inferSymbolMaxVal and compare against the computed limit as described above.

5) Scope and limitations
- The checker focuses on direct multiplications in the size argument for scalar allocators. It intentionally does not handle more complex overflow-protected patterns (e.g., array_size helpers) because those won’t present as a direct sizeof * count multiply or will fail the sizeof detection.
- This is a best-effort structural check; if conditions are statically constant-safe or prove bounded under the size limit, it suppresses warnings; otherwise, it warns.

6) Chosen callbacks summary
- checkPostCall:
  - Detect bad allocator calls with multiplied size expressions involving sizeof.
  - Suppress on compile-time constant or provably bounded count (optional).
  - Emit a concise report recommending kcalloc/kmalloc_array.
