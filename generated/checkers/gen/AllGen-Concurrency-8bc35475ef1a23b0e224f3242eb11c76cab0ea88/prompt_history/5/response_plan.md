1) Program state
- No custom program state is needed. This checker can be implemented with a simple AST pattern match over adjacent statements.

2) Callbacks
- Implement only checkASTCodeBody. Perform a lightweight, per-function AST scan to find the “unconditional read before guard” pattern.

3) Detailed steps

A. High-level detection strategy (inside checkASTCodeBody)
- For each function body, visit all CompoundStmt blocks.
- Within each CompoundStmt, examine adjacent pairs of statements [Si, Si+1].
- Identify Si as an assignment of a local variable from a suspicious shared-field read.
- Identify Si+1 as an IfStmt whose condition tests a guard (from_cancel) and also references the assigned variable.
- If both conditions hold, report a bug: the field read must be moved under the guard.

B. Extract and classify statements (CompoundStmt scan)
- Iterate each CompoundStmt’s children in order:
  - Recognize assignment in Si:
    - Case 1: DeclStmt with exactly one VarDecl VD with an initializer Init.
      - LHS variable is VD, RHS is Init.
    - Case 2: BinaryOperator BO with opcode BO_Assign.
      - LHS is BO->getLHS(), RHS is BO->getRHS().
  - Recognize IfStmt in Si+1:
    - Succeed only if Si+1 is an IfStmt.
    - Let Cond = IfStmt->getCond().

C. Heuristic to recognize a suspicious shared-field read (isSuspiciousSharedRead)
- Input: RHS Expr*.
- Return true if RHS matches either of the following sub-patterns:
  - Pattern A: dereference of a function returning pointer to work->data:
    - RHS contains a CallExpr whose callee name contains “work_data_bits”.
      - Implement by:
        - findSpecificTypeInChildren<CallExpr>(RHS) to get the call.
        - If found, check callee’s identifier name with getNameAsString() or ExprHasName(RHS, "work_data_bits").
    - Optionally accept the presence of a UnaryOperator ‘*’ on top; not strictly required.
  - Pattern B: direct field read of work->data:
    - RHS is a MemberExpr ME with:
      - ME->getMemberDecl()->getNameAsString() == "data".
      - ME->isArrow() is true (pointer field access).
      - Additionally, base expression text contains “work” to narrow to work_struct:
        - ExprHasName(ME->getBase(), "work").
- Keep the heuristic narrow to reduce false positives: accept only if either Pattern A or Pattern B matches.

D. Verify the guard condition uses the assigned variable and checks the guard
- We need the LHS variable declared in Si (VD or the DeclRefExpr on LHS of BO). Get its name (LHSName) and region if needed.
- On Si+1’s IfStmt:
  - Get Cond = IfStmt->getCond()->IgnoreParenImpCasts().
  - Check the guard:
    - Require that Cond contains the name “from_cancel”. Use ExprHasName(Cond, "from_cancel").
  - Check the use of assigned variable:
    - Require that Cond contains the LHS variable name: ExprHasName(Cond, LHSName).
  - Optionally, further constrain:
    - If Cond is a BinaryOperator with opcode BO_LAnd (logical &&), accept it directly (typical in the buggy pattern). Otherwise, still accept if both names appear to catch forms like if (from_cancel) { if (data & …) … } (optional).
- For simplicity and precision, require the adjacent-statement pattern: Si is the assignment, Si+1 is the IfStmt. This matches the kernel pattern and avoids noise.

E. Report
- When a match is found, emit a BasicBugReport (or PathSensitiveBugReport if convenient) with:
  - Short message: “Unconditional read of shared field before checking guard; move the read under the ‘from_cancel’ check.”
  - Location: point to the suspicious RHS read expression (the CallExpr or MemberExpr), or to the assignment statement Si.
- Use generateNonFatalErrorNode if needed to obtain a bug location node, but since this is an AST-only check in checkASTCodeBody, BasicBugReport is sufficient.

4) Utility functions usage
- findSpecificTypeInChildren<CallExpr>(RHS): to find the underlying call (e.g., work_data_bits).
- ExprHasName(expr, "from_cancel"): to detect the guard occurrence in the if condition.
- ExprHasName(expr, "work") and checking MemberExpr name “data”: to recognize work->data field access.
- Optionally, ExprHasName(Cond, LHSName): to confirm the use of the assigned temporary in the guard condition.

5) Notes and scope control
- This checker is intentionally narrow:
  - It only warns when the suspicious read is immediately followed by an if that checks “from_cancel” and uses the assigned temporary.
  - It focuses on work->data or work_data_bits(...) to match the kernel pattern and reduce false positives.
- No alias tracking or path-sensitive state is needed, as we only analyze adjacent statements within the same basic block.
