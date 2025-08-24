1) Program state
- No custom program state is required. This checker is a call-site pattern detector that inspects allocation calls and their size expressions on the fly.

2) Callback functions
- Use only checkPreCall.

3) Detailed steps

Step A. Identify target allocators in checkPreCall
- When checkPreCall is invoked, inspect the callee name via Call.getCalleeIdentifier()->getName().
- Only proceed if the function is one of:
  - "kmalloc", "kzalloc" (optionally, you may include "__kmalloc" or "kvzalloc" if desired; the core pattern is for kmalloc/kzalloc).
- For these functions, retrieve the first argument (size expression) with Call.getArgExpr(0). Let this be ESize.

Step B. Normalize and extract a multiplicative size expression
- Strip parens and implicit casts from ESize using ESize = ESize->IgnoreParenImpCasts().
- Try dyn_cast<BinaryOperator>(ESize); if not a BinaryOperator, try findSpecificTypeInChildren<BinaryOperator>(Call.getArgExpr(0)) to handle wrapping casts/macros. If still not found, return (no bug).
- If found, ensure the operator is multiplication: BinOp->getOpcode() == BO_Mul. If not, return.

Step C. Detect the “sizeof * count” pattern
- Extract LHS and RHS as ELHS = BinOp->getLHS()->IgnoreParenImpCasts(), ERHS = BinOp->getRHS()->IgnoreParenImpCasts().
- Check if either side is a sizeof expression:
  - dyn_cast<UnaryExprOrTypeTraitExpr>(ELHS) with getKind() == UETT_SizeOf, or
  - dyn_cast<UnaryExprOrTypeTraitExpr>(ERHS) with getKind() == UETT_SizeOf.
- If neither side is a sizeof expression, return (we only warn on the clear sizeof * count pattern; this keeps false positives low).
- Let ESizeOf be the sizeof side; let ECount be the other side.

Step D. Filter out trivially safe cases (constant size)
- Try to evaluate the entire size expression ESize to a constant with EvaluateExprToInt(..., ESize, C). If it evaluates to a compile-time constant (i.e., APSInt available), do not warn, return. Rationale: constant folded size is under the programmer’s control and typically not a user-driven overflow risk.
- Else, evaluate the sizeof side ESizeOf to a constant using EvaluateExprToInt(..., ESizeOf, C). This should usually succeed; if not, continue but keep the warning conservative.

Step E. Try to prove the multiplication cannot overflow; otherwise, warn
- Attempt to evaluate the count side ECount to a constant:
  - If EvaluateExprToInt(..., ECount, C) succeeds, optionally (but simply) skip warning because both factors are known and the total size was not constant-folded only due to type/implicit cast wrapping. For simplicity, treat constant count as low risk and return without warning.
- If ECount is not a compile-time constant:
  - Obtain the symbolic value of ECount: SVal CountSV = C.getState()->getSVal(ECount, C.getLocationContext()).
  - If CountSV.getAsSymbol() yields Sym, try inferSymbolMaxVal(Sym, C).
    - If a max value is known (MaxCount), and the product (MaxCount * SizeOfVal) fits into the bitwidth of ESize’s type (typically size_t; you can get width via C.getASTContext().getTypeSize(ESize->getType())), then consider it safe and return.
    - If max value is unknown or the product may overflow, proceed to report.
- Heuristic policy (to stay simple and effective):
  - If we detect kmalloc/kzalloc with a multiplicative size argument where one factor is sizeof(...) and the other is a non-constant expression whose maximum cannot be proven safe, emit a warning recommending kcalloc(n, size, flags).
  - This matches the given patch pattern and is sufficient to catch common user-count-driven allocations.

Step F. Reporting
- Create a BugType once (e.g., in the checker’s constructor or lazily on first use) with a short name like "Potential overflow in kmalloc/kzalloc size".
- Generate a non-fatal error node with generateNonFatalErrorNode().
- Build a PathSensitiveBugReport with a short message:
  - "Use kcalloc(n, size) to avoid overflow in kmalloc/kzalloc size computation."
- Highlight the source range of the first allocation argument (ESize).
- Optionally, add an extra note range for the count expression (ECount) to point to the likely user-derived factor.
- Emit the report with C.emitReport(...).

4) Notes and small helpers
- Function matching:
  - Implement a small helper isKernelAlloc(const CallEvent &Call) that returns true if the callee name equals "kmalloc" or "kzalloc".
- Multiplication extraction:
  - Prefer direct dyn_cast<BinaryOperator> on the unwrapped size expression; if this fails, fall back to findSpecificTypeInChildren<BinaryOperator>(Call.getArgExpr(0)) to catch cases hidden by casts/macros.
- sizeof extraction:
  - Check UnaryExprOrTypeTraitExpr on the direct operand. This avoids relying on textual matching and keeps the logic robust.
- Integer evaluation:
  - Use the provided EvaluateExprToInt utility.
- Max bound reasoning:
  - Use inferSymbolMaxVal for simple pruning. If no bounds available, warn.

This minimal, call-site-only checker will reliably flag kmalloc/kzalloc calls that compute their size as sizeof(T) * n without overflow checks, and guide developers toward kcalloc, matching the target patch and bug pattern.
