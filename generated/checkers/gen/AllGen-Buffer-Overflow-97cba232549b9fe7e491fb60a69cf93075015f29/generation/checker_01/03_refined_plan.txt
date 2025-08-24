Plan: Detect off-by-one loop bound when dereferencing arr[i + 1]

1) Program state
- No custom program state is needed. This checker is a purely syntactic/semantic pattern matcher over the AST.

2) Callbacks and implementation steps

A) checkASTCodeBody (the only callback needed)
- Goal: Walk each function body and find for-loops that iterate with i < Bound while the body dereferences arr[i + 1] without a guard. Report once per offending loop.
- Implementation details:
  1. Build a lightweight AST walker (RecursiveASTVisitor or manual Stmt traversal) inside checkASTCodeBody to visit every ForStmt.
  2. For each ForStmt FS, extract the loop induction variable and the loop bound:
     - Read FS->getCond() and match a BinaryOperator with operator '<' (and also handle the symmetrical form Bound > i).
       - Case A: LHS is a DeclRefExpr to a VarDecl IVar, RHS is BoundExpr (UB).
       - Case B: LHS is BoundExpr (UB), RHS is DeclRefExpr to VarDecl IVar.
     - If neither pattern matches, skip this loop.
     - (Optional robustness) Confirm FS->getInc() references IVar (pre/post increment, or compound assignment). If not, skip as a non-standard pattern.
  3. Scan the loop body FS->getBody() for array subscripts of the form arr[i + 1]:
     - Traverse all ArraySubscriptExpr nodes in the loop body.
     - For each candidate ASE:
       - Let Index = ASE->getIdx()->IgnoreParenImpCasts().
       - Check if Index is exactly a BinaryOperator with op '+' and one side is DeclRefExpr to IVar and the other side is integer literal 1 (use EvaluateExprToInt for robustness after ignoring implicit casts).
         - Accept both (i + 1) and (1 + i).
       - If this does not hold, continue scanning.
  4. Guard detection (to avoid false positives):
     - For the found ASE that uses (i + 1), check if it is guarded by a condition that constrains i accordingly.
       - Find the nearest enclosing IfStmt using findSpecificTypeInParents<IfStmt>(ASE, C) (if within an if).
       - If found, examine its condition expression Cond:
         - Consider it a guard if Cond implies either:
           - (i + 1) < something, or
           - i < something - 1
         - Heuristics to detect above without heavy symbolic reasoning:
           - Use ExprHasName(Cond, IVar->getName(), C) to ensure i appears in the condition.
           - Additionally, check for “+ 1” or “+1” around i, or “- 1” or “-1” on the bound side:
             - For example, string checks:
               - ExprHasName(Cond, (IVarName + " + 1").str(), C) OR
               - ExprHasName(Cond, (IVarName + "+1").str(), C) OR
               - (ExprHasName(Cond, IVarName, C) && ExprHasName(Cond, "- 1", C)) OR
               - (ExprHasName(Cond, IVarName, C) && ExprHasName(Cond, "-1", C))
           - If any of these simple guard patterns are found in the condition, treat the access as guarded and skip reporting for this ASE.
     - If not inside any IfStmt, or the condition does not contain these guard patterns, proceed to report.
     - Note: We intentionally do not require that the guard uses the exact same bound expression UB, to keep the checker simple and reduce false positives from complex bound expressions. Any local guard that ensures i is capped by bound-1 (or checks i+1) is considered sufficient.
  5. Reporting:
     - Once an unguarded arr[i + 1] use is identified under a loop condition of i < UB or UB > i, produce one report per ForStmt (avoid duplicates by keeping a small local set of reported loops or by early return after first emission in this loop).
     - Create a static BugType (e.g., "Off-by-one look-ahead array access").
     - Use BasicBugReport with location at ASE->getExprLoc().
     - Message: "Off-by-one: loop uses 'i < bound' but accesses element at 'i + 1'. Use 'i < bound - 1' or guard the access."
     - Emit the report via BR.emitReport(...).

3) Helper routines (local to the checker, simple and robust)
- getLoopVarAndBound(const ForStmt *FS, VarDecl *&IVar, const Expr *&UB):
  - Parse FS->getCond(), match i < UB or UB > i and retrieve IVar and UB as described.
- isIndexVarPlusOne(const Expr *Idx, const VarDecl *IVar, CheckerContext &C):
  - Ignores casts/paren.
  - Checks BinaryOperator '+' with one side DeclRefExpr to IVar and the other side integer literal 1 (use EvaluateExprToInt to confirm value 1).
- isGuardingConditionForLookAhead(const IfStmt *IS, const VarDecl *IVar, CheckerContext &C):
  - Get Cond = IS->getCond().
  - Use ExprHasName to look for IVar and either "+ 1"/"+1" or "- 1"/"-1" as described.
  - Return true if any guard pattern detected.

4) Optional refinements (keep simple if not needed)
- Also consider '<=' by treating i <= UB - 2 as safe; you can add that to the guard detection patterns by checking for "- 2" if desired.
- Generalize to arr[i + K], K is constant > 0:
  - If EvaluateExprToInt finds constant K > 0 on the index side, then require a guard for i < bound - K or (i + K) < bound; but keep the first version to K == 1 for simplicity.

5) Where to use provided utilities
- findSpecificTypeInParents<IfStmt> to locate a guarding IfStmt for a given ArraySubscriptExpr.
- EvaluateExprToInt to decode the literal 1 on the index side robustly.
- ExprHasName to cheaply recognize textual patterns of i+1 or -1 in guard conditions without building complex expression matchers.

This plan focuses on the simplest reliable detection of the target pattern seen in the patch: a for-loop with i < size that dereferences arr[i + 1] in its body without checking i < size - 1 (or (i + 1) < size).
