Plan to detect “algorithmically computed index not validated against TRANSFER_FUNC_POINTS” in LUT array accesses

1. Program state
- No custom program state is required. This checker can be implemented as a syntactic-plus-local-structural analysis around array subscripts.

2. Callbacks and high-level flow
- checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const
  - Core detection happens here. We:
    - Identify accesses to the fixed-size LUT arrays tf_pts.{red,green,blue}[i].
    - Extract the index expression and its variable name (e.g., “i”).
    - Search for a dominating guard in the nearest enclosing compound statement that checks the index against TRANSFER_FUNC_POINTS and exits the path (e.g., return/break) when it is out of bounds.
    - If no such guard is found, emit a bug report.

3. Detailed implementation per callback

- checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C)
  1) Filter to target LUT arrays:
     - Get the base expression: const Expr *Base = ASE->getBase()->IgnoreParenImpCasts().
     - Ensure it is indexing one of tf_pts.{red,green,blue}:
       - Prefer structural check:
         - Try dyn_cast<MemberExpr>(Base). If success, inspect the field name (getMemberDecl()->getName()) and check if it is one of "red", "green", "blue".
         - For the base of that MemberExpr, dyn_cast<MemberExpr> again and check that inner member name is "tf_pts".
       - As a fallback/heuristic (to be robust against implicit casts or macro text), accept Base if:
         - ExprHasName(Base, "tf_pts") AND (ExprHasName(Base, "red") OR "green" OR "blue").
     - If neither structural nor heuristic checks match, return.

  2) Extract the index variable name:
     - const Expr *IdxE = ASE->getIdx()->IgnoreParenImpCasts().
     - If IdxE is a DeclRefExpr to a VarDecl, capture the variable name as StringRef IdxName = VD->getName().
     - If IdxE is not a simple variable (e.g., complex expression), you can still attempt a heuristic by pulling the source text via ExprHasName and searching for an identifier, but to keep it simple and precise, only proceed when IdxE is a DeclRefExpr.

  3) Find a dominating bounds check against TRANSFER_FUNC_POINTS:
     - Find the nearest enclosing CompoundStmt of ASE:
       - const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(ASE, C).
       - If no CompoundStmt is found, report (conservative) or simply return; prefer to return to avoid false positives.
     - Within CS, determine the “containing” top-level statement that has ASE somewhere in its subtree:
       - Iterate for (Stmt *Child : CS->body()) and find the first Child that contains ASE in its subtree (you can do a small DFS walk from Child to see if ASE pointer is found).
       - Record the index position P of that Child in the compound’s sequence.
     - Scan all statements before P (from P-1 down to 0) to find a guard IfStmt:
       - For each previous Stmt Prev:
         - IfStmt *If = dyn_cast<IfStmt>(Prev); if not, continue.
         - const Expr *Cond = If->getCond();
         - Check that Cond mentions both the index name and TRANSFER_FUNC_POINTS:
           - ExprHasName(Cond, IdxName) AND ExprHasName(Cond, "TRANSFER_FUNC_POINTS").
         - Additionally, confirm that the “guard” branch exits the current flow:
           - Define a helper bool branchExits(const Stmt *S) that recursively searches for a ReturnStmt or BreakStmt within S (any depth).
           - Treat as valid guard if branchExits(If->getThen()) is true OR branchExits(If->getElse()) is true.
             - This covers both common styles:
               - if (i >= TRANSFER_FUNC_POINTS) return/break;
               - if (i < TRANSFER_FUNC_POINTS) { … use array … } else return/break;
         - If such a guard is found, consider the access protected and stop checking.
     - If no guard is found, report a potential out-of-bounds index.

  4) Emit a report:
     - Create a non-fatal error node with C.generateNonFatalErrorNode().
     - Use a PathSensitiveBugReport with a short message, e.g.:
       - “Index may exceed TRANSFER_FUNC_POINTS when indexing LUT array.”
     - Attach the ArraySubscriptExpr as the location using addRange(ASE->getSourceRange()) and/or mark the array access as the interesting location.

4. Auxiliary helpers to implement
- baseIsTfPtsRGB(const Expr *Base):
  - Structural approach with MemberExpr chain for ".tf_pts.(red|green|blue)".
  - Fallback heuristic using ExprHasName(Base, "tf_pts") and one of channel names.

- getIndexVarName(const Expr *IdxE, StringRef &Out):
  - If DeclRefExpr to VarDecl, set Out = VD->getName() and return true; otherwise return false.

- stmtContains(const Stmt *Root, const Stmt *Target):
  - Small DFS to determine if Target pointer appears somewhere under Root.

- branchExits(const Stmt *S):
  - DFS over S to see if a ReturnStmt or BreakStmt exists.

- hasDominatingGuard(const Stmt *UseSite, StringRef IdxName, CheckerContext &C):
  - Implements the CompoundStmt scan logic described above.

5. Notes and constraints
- This checker intentionally focuses on the LUT arrays under tf_pts and TRANSFER_FUNC_POINTS. It is tuned to the exact bug pattern in the patch:
  - Accesses to output_tf->tf_pts.{red,green,blue}[i] created by algorithmic computation of i.
  - Missing explicit guard against TRANSFER_FUNC_POINTS before the access.
- Heuristic-based detection is used (identifier names and presence of return/break in the guard), which keeps the checker simple and practically useful while avoiding path-sensitive state machinery.
- We do not rely on constant folding of TRANSFER_FUNC_POINTS; we only require that the condition mentions the macro name (via ExprHasName(..., "TRANSFER_FUNC_POINTS")).
- We do not maintain alias/taint maps or track index constraints; the goal is to enforce an explicit bounds check pattern around the access for this specific LUT case.

6. Callback summary
- checkPreStmt(ArraySubscriptExpr):
  - Detect target base tf_pts.{red,green,blue}.
  - Extract index var name.
  - Search for dominating guard comparing index with TRANSFER_FUNC_POINTS and exiting.
  - If absent, report.

This plan uses the simplest effective approach, avoids custom program state, and directly targets the missing-guard bug pattern demonstrated in the provided patch.
