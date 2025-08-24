Plan

1. Program state
- No custom program states are needed. This checker is a local pattern detector at allocation call sites.

2. Chosen callbacks
- checkPreCall: Inspect allocation calls and their size arguments before they are evaluated, detect the multiplication pattern, and decide whether to report.

3. checkPreCall implementation details
- Identify target functions:
  - Warn only on allocation functions that take a single “total size” argument:
    - kmalloc(size, flags), kzalloc(size, flags), __kmalloc(size, flags), kmalloc_node(size, flags, node), kzalloc_node(size, flags, node),
    - vmalloc(size), vzalloc(size), __vmalloc(size, flags, prot),
    - kvmalloc(size, flags), kvzalloc(size, flags), kvmalloc_node(size, flags, node)
  - Do not warn for kcalloc/kvcalloc (these are already safe).
  - Implementation:
    - From CallEvent, get callee Identifier and compare to a NameSet of the above functions.
    - Determine the index of the “size” parameter. For all above functions, it is arg index 0.

- Extract and normalize the size expression:
  - Get Expr *SizeArg = Call.getArgExpr(0) and strip parens/implicit casts with IgnoreParenImpCasts.

- Detect multiplication pattern:
  - Use findSpecificTypeInChildren<BinaryOperator>(SizeArg) to locate a BinaryOperator.
  - If none found or opcode != BO_Mul, return (no warning).
  - Optional precision: also confirm there is a UnaryExprOrTypeTraitExpr with kind UETT_SizeOf somewhere under SizeArg:
    - Use findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(SizeArg). If not found or not UETT_SizeOf, return to reduce false positives.
  - This focuses on the risky pattern sizeof(T) * count (or count * sizeof(T)).

- Filter out obvious safe constants:
  - If EvaluateExprToInt(EvalRes, SizeArg, C) succeeds (compile-time constant), return (no warning). This avoids noise for constant expressions that the compiler already evaluated safely.

- Try a lightweight overflow feasibility check (optional but simple and useful):
  - Identify the “count” operand if possible:
    - From the multiplication BO, let LHS = BO->getLHS()->IgnoreParenImpCasts(), RHS likewise.
    - If one side is UnaryExprOrTypeTraitExpr UETT_SizeOf, pick the other side as CountExpr and record ElemSize:
      - Evaluate Expr to integer for sizeof side using EvaluateExprToInt to get ElemSize.
      - If both sides are sizeof/constant (unlikely), return (not a real count pattern).
  - Check if count is safely bounded:
    - Try EvaluateExprToInt on CountExpr; if it succeeds, the product is still non-constant only if CountExpr was constant, but evaluation on the whole SizeArg would have succeeded. In practice, if CountExpr is constant and ElemSize is constant, SizeArg is constant; we already returned. So skip.
    - Else, get SVal CountVal = State->getSVal(CountExpr, C.getLocationContext()) and see if it is a Symbol (SymbolRef).
    - If SymbolRef available, call inferSymbolMaxVal(SymbolRef, C).
      - If we get a max value (MaxCount) and we have ElemSize, compute:
        - size_t bit width: use C.getASTContext().getTypeSize(C.getASTContext().getSizeType()) to create a MaxSize APInt of all ones.
        - Form APInt(ElemSizeBits) for ElemSize and zero-extend as needed.
        - Multiply APInts: MaxCount * ElemSize and compare to MaxSize. If product <= MaxSize, return (no warning).
      - If we cannot obtain MaxCount or ElemSize, continue to warning.
  - If any of the above bounding checks fail (unknown or potentially exceeding size_t), proceed to report.

- Report:
  - Create a non-fatal error node with C.generateNonFatalErrorNode().
  - Create a PathSensitiveBugReport with a concise message, for example:
    - "Unchecked size multiplication in kmalloc/kzalloc; use kcalloc to avoid overflow."
  - Attach the source range of SizeArg to the report.
  - Emit the report via C.emitReport(...).

4. Helper utilities to leverage
- findSpecificTypeInChildren<T> to detect BinaryOperator (multiply) and UnaryExprOrTypeTraitExpr (sizeof).
- EvaluateExprToInt to identify constant expressions and element size constants.
- inferSymbolMaxVal to obtain an upper bound for the count operand.
- getSourceManager and source range APIs (already available in CheckerContext) to highlight SizeArg properly.

5. Suppressions and scope
- Do not warn when:
  - The callee is kcalloc/kvcalloc (already safe).
  - The “size” argument is a compile-time constant (EvaluateExprToInt succeeds for the whole SizeArg).
  - A provable upper bound on count guarantees no overflow as per the simple max bound check described above.
- Otherwise, warn, since the pattern sizeof(...) * count passed as a “total size” argument is prone to integer overflow and should be replaced by kcalloc or array_size/struct_size helpers.

6. No other callbacks needed
- No need for checkPostCall, checkBind, or checkBranchCondition in this checker. The entire detection is contained within checkPreCall.
