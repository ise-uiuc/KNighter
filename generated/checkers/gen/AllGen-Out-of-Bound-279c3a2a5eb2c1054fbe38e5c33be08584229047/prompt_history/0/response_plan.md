Plan

1) Program state
- No custom program states are necessary. We can detect this as a purely syntactic/semantic (AST-level) pattern within a single function body.

2) Callbacks to use
- checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR)
  Reason: The pattern is a local, flow-light condition in a function (an off-by-one guard “> MAX” guarding later array indexing). We can match it directly by walking the AST of the function body, avoiding path-sensitive state.

3) Overall detection strategy (within checkASTCodeBody)
- For each function body (D has a statement body), traverse the AST and:
  a) Find IfStmts whose condition contains a “strict upper bound” integer comparison on an index variable (idx > MAX or MAX < idx).
  b) Ensure the “then” branch contains a ReturnStmt (typical early-return guard). This greatly reduces false positives (it matches the common “validate then return -EINVAL” idiom).
  c) Extract the compared index variable and the bound constant value (MAX).
  d) After this IfStmt (in source order), find any array subscript expressions A[idx]. For each:
     - Identify the array’s compile-time size (when possible).
     - If the array size equals MAX (the same bound used in the guard), report: the check “> MAX” incorrectly allows idx == MAX.
  e) Emit a single report per found pattern.

4) Detailed implementation steps

Step 4.1: Traverse the function body
- In checkASTCodeBody, get the body stmt (cast the Decl to FunctionDecl/ObjCMethodDecl/etc., and get the body).
- Perform a recursive AST walk over the body. For each IfStmt, apply the steps below.

Step 4.2: Identify a “strict upper bound” guard in the If condition
- Extract the condition Stmt* Cond = If->getCond().
- Within Cond, search for BinaryOperator nodes that are strict comparisons where the relational operator is:
  - BO_GT (idx > MAX) or BO_LT (MAX < idx)
- Conditions are often compound (e.g., idx > MAX || type != X). Handle this by recursively scanning all children of Cond; when you encounter a BinaryOperator with ‘||’/‘&&’, keep diving until you find a BO_GT/BO_LT.
- When you find a BO_GT/BO_LT, try to identify sides:
  - Case 1: LHS is the index variable; RHS is the bound.
  - Case 2: LHS is the bound; RHS is the index variable (for <).
- Index expression constraints:
  - Prefer a DeclRefExpr to a VarDecl (e.g., “int adc_chan”), and record VarDecl* IdxVar. Ignore more complex expressions to keep the checker simple and precise.
- Bound expression constraints:
  - Try to evaluate it to an integer using EvaluateExprToInt(APSInt &Out, const Expr *E, CheckerContext &C).
  - If evaluation fails, skip this candidate (we only warn when the bound is a known constant).
- If multiple BO_GT/BO_LT candidates exist in the same If condition, you can handle any that match the pattern (typically there’s just one for the index).

Step 4.3: Ensure it is an early-return guard
- Inspect the IfStmt’s then-branch (If->getThen()) and check if it contains any ReturnStmt using findSpecificTypeInChildren<ReturnStmt>(Then).
- If there is no ReturnStmt in the then-branch, skip this If (reduces false positives).

Step 4.4: Find array subscripts later that use the same index variable
- From the function body, collect ArraySubscriptExpr nodes whose index expression is the same IdxVar (DeclRefExpr to the same VarDecl).
- For each such ArraySubscriptExpr ASE:
  - Ensure the ASE occurs after the IfStmt in source order:
    - Use SourceManager::isBeforeInTranslationUnit(IfLoc, ASELoc) to enforce “guard first, use later”.
  - Determine the array base and its compile-time size:
    - Let BaseE = ASE->getBase()->IgnoreParenImpCasts().
    - If BaseE is a DeclRefExpr referring to a VarDecl of constant array type, use the provided helper getArraySizeFromExpr(ArraySize, BaseE). If it returns true, we got the array size.
    - Else if BaseE is a MemberExpr (e.g., adc->thresholds), retrieve the FieldDecl* FD = cast<FieldDecl>(ME->getMemberDecl()), then get its type QualType FT = FD->getType(); if FT is ConstantArrayType, obtain its size via cast<ConstantArrayType>(FT.getTypePtr())->getSize().
    - If neither yields a constant array size, skip this ASE (we only warn on known sizes).
  - Compare the array size (APInt) and the bound (APSInt). Normalize bit-width/sign and compare numerically. If equal, this is the precise “off-by-one” case we want.

Step 4.5: Report the bug
- Once a matching ASE is found, emit one report per IfStmt (avoid duplicates for multiple uses).
- Preferred report location: the comparison operator inside the If condition (the BO_GT/BO_LT node). If unavailable, use If->getIfLoc().
- Message (short and clear):
  - “Off-by-one bound check: ‘> MAX’ allows idx == MAX; use ‘>= MAX’.”
- Use a BasicBugReport with a custom BugType or a PathSensitiveBugReport is fine, but BasicBugReport is sufficient in checkASTCodeBody.

5) Heuristics and corner cases
- Logical-OR conditions: It is common to see “if (idx > MAX || other_check) return -EINVAL;”. Only the strict upper bound part matters; accept this form.
- Reversed comparison: Support both idx > MAX and MAX < idx. Do not flag non-strict or unrelated comparisons.
- Multiple arrays: If multiple arrays indexed by the same idx exist, warn as soon as you find one whose size equals MAX. Do not spam multiple reports per If; one is enough.
- Reduce false positives: Require an early return inside the then-branch. Also require both bound and array size to be compile-time constants and equal.

6) Utility functions to use
- EvaluateExprToInt for extracting the integer value of “MAX” from the condition.
- findSpecificTypeInChildren<ReturnStmt> to verify early-return guard.
- getArraySizeFromExpr for DeclRefExpr base arrays.
- For MemberExpr bases, inspect the FieldDecl’s type and check for ConstantArrayType.
- ExprHasName can be used optionally to further reduce noise (e.g., if you want to check that the base array or idx name matches a pattern), but is not required.

7) Optional extension (not necessary for the simplest working checker)
- Support check::BranchCondition in addition to checkASTCodeBody:
  - Detect the strict upper bound guard in checkBranchCondition, store a lightweight “candidate” tuple (IdxVarDecl*, BoundValue, IfStmtLoc) in a function-scoped vector (no ProgramState).
  - Still do the array subscript scan and reporting in checkASTCodeBody using the collected candidates.
- This can improve modularity but is not required for correctness.

This plan yields a simple, robust checker that flags the precise bug pattern: guarding an index with “> MAX” (strict) and later indexing arrays sized exactly MAX, which allows idx == MAX to slip through and cause out-of-bounds access.
