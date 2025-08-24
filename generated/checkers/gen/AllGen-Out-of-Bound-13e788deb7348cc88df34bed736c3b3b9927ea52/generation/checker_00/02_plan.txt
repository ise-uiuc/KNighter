1) Program state
- No custom program state is required. We can detect this pattern locally in the branch condition and avoid tracking across statements.

2) Callbacks to use
- checkBranchCondition only.

3) Detailed steps

Step A: Detect the faulty guard in checkBranchCondition
- Input: const Stmt *Condition is the expression that guards an if/else, while, for, etc. We will only act when it is from an IfStmt.
- Implementation:
  1) Retrieve the enclosing IfStmt using findSpecificTypeInParents<IfStmt>(Condition, C). If not found, return.
  2) Require that Condition is a BinaryOperator with one of these forms:
     - BO_GT: (LHS > RHS)
     - BO_LT: (LHS < RHS)  // equivalent to RHS > LHS
     Ignore other operators. If it is a BinaryOperator chain (like a &&/||), skip.
  3) Normalize the comparison:
     - For BO_GT: VarExpr = LHS, BoundExpr = RHS.
     - For BO_LT: VarExpr = RHS, BoundExpr = LHS.  // rewrite “MAX < idx” as “idx > MAX”
  4) Validate BoundExpr as a “MAX-like bound”:
     - Try to evaluate BoundExpr to an integer using EvaluateExprToInt. If it evaluates, keep the value (we don’t strictly need it to report, but this helps in avoiding non-integer cases).
     - Additionally, ensure the bound looks like an upper-bound constant:
       - If BoundExpr’s source text contains "MAX" (ExprHasName(BoundExpr, "MAX", C) == true), or
       - BoundExpr is a DeclRefExpr and its decl name contains "MAX" (DRE->getDecl()->getName().contains("MAX")).
     If neither test passes, return (reduces false positives).
  5) Verify this is an error-guard:
     - Grab IfStmt->getThen(). If null, return.
     - Check whether the Then branch contains an early-exit (error) using findSpecificTypeInChildren<ReturnStmt>(IfStmt->getThen()).
     - If no ReturnStmt found, optionally accept a stricter guard by also checking for a call to common error paths (not required for minimal version). For the simplest version, require a ReturnStmt and otherwise return.
  6) Optional sanity: If VarExpr is a literal (not a variable/expression), skip to avoid nonsense.
  7) Report:
     - Create a BasicBugReport (or PathSensitiveBugReport if you prefer a path note) with a short message:
       “Off-by-one bound check: use ‘>= MAX’ instead of ‘> MAX’ for index validation.”
     - Anchor it at the condition expression or the operator location.
     - Use C.emitReport(std::make_unique<BasicBugReport>(...)).

Notes and heuristics
- This checker purposefully keeps the logic simple and local:
  - It flags guards that are highly likely meant to constrain an index to [0..MAX-1] but use ‘> MAX’ instead of ‘>= MAX’.
  - It reduces false positives by:
    - Requiring a MAX-like bound token in the source.
    - Requiring the guard lead to an early return in the then-branch (common error-check idiom).
- No alias or dataflow tracking is needed.
- No need to inspect later array subscripts; the guard itself is the bug in the target patch.

4) Summary of used utilities and APIs
- findSpecificTypeInParents<IfStmt>(Condition, C) to obtain the IfStmt from the branch condition.
- findSpecificTypeInChildren<ReturnStmt>(IfStmt->getThen()) to confirm it is an error-guard branch.
- EvaluateExprToInt to ensure the right-hand side is an integer constant (best-effort).
- ExprHasName(BoundExpr, "MAX", C) to robustly detect “MAX” in the bound’s token text.
