1) Program state
- Do not introduce any custom program state. This checker can be implemented as a purely AST-pattern detector; no inter-path reasoning or alias tracking is required.

2) Callbacks and high-level flow
- Use checkASTCodeBody to scan function bodies and detect the target pattern in loop constructs.
- No other callbacks are necessary.

3) Loop and induction variable identification (in checkASTCodeBody)
- Traverse the body’s AST and focus on ForStmt nodes (optionally extend to WhileStmt later; start with ForStmt to keep it simple).
- For each ForStmt FS:
  - Extract the induction variable i:
    - From FS->getInit():
      - DeclStmt: single VarDecl with integer type, record the VarDecl* IVar (initializer can be ignored).
      - Or BinaryOperator ‘=’: LHS should be DeclRefExpr to a variable; record that variable as IVar.
  - Extract the loop condition Cond:
    - Must be a BinaryOperator with one of the following:
      - i < Bound
      - Bound > i
      - i <= BoundMinusOne (safe bound; skip)
      - BoundMinusOne >= i (safe bound; skip)
    - Normalize to determine:
      - IsStrictUpperBound: true if it is strictly i < Bound or Bound > i.
      - IsMinusOneAdjusted: true if the non-strict case uses “- 1” (i <= Bound - 1 or Bound - 1 >= i). If IsMinusOneAdjusted, skip reporting for this loop, as it already enforces i+1 < Bound.
    - For strict cases (IsStrictUpperBound == true), further check that the RHS/LHS is not an explicit “... - 1” to avoid false positives when the author already used (Bound - 1) explicitly:
      - If the Bound side is a BinaryOperator ‘-’ with RHS IntegerLiteral(1), treat as IsMinusOneAdjusted and skip.
  - Extract the increment Inc:
    - Prefer simple forms: i++, ++i, i += 1, or i = i + 1. If increment does not affect i or is not a unit-step increment, skip the loop to reduce false positives.

4) Finding suspicious array accesses a[i + 1]
- Within the loop body FS->getBody(), recursively visit ArraySubscriptExpr (ASE) nodes.
- For each ASE:
  - Let Idx = ASE->getIdx()->IgnoreParenImpCasts().
  - Check if Idx is exactly i + 1 (or 1 + i):
    - BinaryOperator ‘+’ with operands (DeclRefExpr to IVar, IntegerLiteral(1)) or (IntegerLiteral(1), DeclRefExpr to IVar).
    - Ignore all other offsets or complex expressions to keep checker simple and precise.
- If an a[i + 1] access is found and the loop’s IsStrictUpperBound is true (from step 3), this is a candidate for off-by-one risk.

5) Guard detection to reduce false positives
- Before reporting for an ASE, try to detect a local guard:
  - Walk up the AST from ASE using findSpecificTypeInParents to find the nearest enclosing IfStmt that is inside the same loop body (stop when reaching the ForStmt).
  - Inspect the IfStmt’s condition:
    - If the condition is of the form:
      - i + 1 < X (i.e., BinaryOperator ‘<’ or ‘<=’ where LHS is i + 1), or
      - i < X - 1 (LHS i; RHS BinaryOperator ‘-’ with IntegerLiteral(1)),
      then treat as guarded and do not report.
  - Implementation details:
    - For i + 1 < X: condition is BinaryOperator with opcode LT or LE, whose LHS is BinaryOperator ‘+’ (i, 1) or (1, i).
    - For i < X - 1: condition is BinaryOperator with opcode LT or LE, whose LHS is i, and RHS is BinaryOperator ‘-’ with IntegerLiteral(1).
  - Optionally, as a fallback in tricky conditions, use ExprHasName on the If condition to look for “i + 1” when AST-matching fails, but prefer AST-based checks first.

6) Reporting
- When a[i + 1] is found, IsStrictUpperBound is true, and no local guard is detected:
  - Create a non-fatal error node with C.generateNonFatalErrorNode().
  - Emit a PathSensitiveBugReport with a short message, e.g.:
    - “Possible off-by-one: loop uses i < bound but also accesses a[i + 1].”
  - Attach the primary location to the ArraySubscriptExpr ‘[i + 1]’.
  - Optionally add a note at the ForStmt condition source location to highlight the i < Bound condition.

7) Notes and heuristics
- Keep matching conservative:
  - Only flag exact i + 1 accesses to avoid noise.
  - Only flag loops where the upper bound is a strict inequality without explicit “- 1”.
  - Require unit-step increment on i.
- Array base expression type is not required to be a fixed-size array; we only care about the logical off-by-one pattern. Do not try to compute array length; the pattern is unsafe regardless of the exact size if the loop condition does not account for the +1 access.
- Utility functions used:
  - findSpecificTypeInParents: to find enclosing IfStmt for guard detection.
  - findSpecificTypeInChildren: can be used if you choose a simpler body-scan approach, but a small recursive visitor over the loop body is straightforward.
  - ExprHasName: optional fallback guard detection when AST pattern fails.

8) Minimal implementation outline per ForStmt
- Extract IVar, Cond, Inc; determine IsStrictUpperBound and IsMinusOneAdjusted.
- If IsStrictUpperBound and not IsMinusOneAdjusted:
  - Scan body for ASE with index i + 1.
  - For each such ASE, check guard via nearest IfStmt as described.
  - If unguarded, report.
