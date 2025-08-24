1) Program state
- No custom program state needed. This checker can be implemented with pattern-based inspection around the write to iter->count. We will rely on local AST inspection and the provided utility helpers.

2) Callbacks and implementation details

A) checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C)
Goal: Detect a subtractive shrink of iter->count that uses an unsigned difference “A - B” where A is the current I/O length and B is a block-aligned length (round_up), without a guard ensuring B <= A (or an equivalent guard, e.g., shorten <= iter->count).

Steps:
1. Filter for writes to iter->count:
   - Ensure Loc is a region for a record field named “count”, and the base type is (or contains) “struct iov_iter”. You can retrieve the FieldRegion and FieldDecl, then check FieldDecl->getName() == "count". Optionally check the base type string contains “iov_iter”.
   - Extract the statement S that caused the bind. It should be:
     - A CompoundAssignOperator “-=” with LHS being “iter->count”, or
     - A BinaryOperator “=” with LHS “iter->count”.
   - If neither, return.

2. Extract the “shrink” expression:
   - If S is a CompoundAssignOperator with “-=”, let ShrinkExpr = the RHS.
   - If S is a BinaryOperator “=”, try to detect the pattern “iter->count = <something>”. If RHS is a BinaryOperator “-”, and one side references the current count (i.e., MemberExpr matching iter->count), then the other side is ShrinkExpr. Otherwise, if RHS is just a variable (e.g., “shorten”), set ShrinkExpr = that variable and resolve it in step 3.

3. Resolve the shrink computation (find “A - B”):
   - If ShrinkExpr is already a BinaryOperator “-”, let DiffExpr = ShrinkExpr.
   - Else if ShrinkExpr is a DeclRefExpr to a variable (e.g., “shorten”), find the most recent assignment/initialization to that variable in the same scope before S:
     - Use findSpecificTypeInParents to get the surrounding CompoundStmt.
     - Iterate the CompoundStmt body, remembering statements until you reach S; track the last DeclStmt or BinaryOperator that defines/assigns the variable. Pick the last one before S.
     - From that defining statement, extract its RHS as DiffExpr.
   - If no definition found or DiffExpr is not a BinaryOperator “-” (or types don’t match below), return.

4. Recognize A and B:
   - Let A = LHS of DiffExpr; B = RHS of DiffExpr.
   - Check that DiffExpr’s type is unsigned (preferably isUnsignedIntegerType()), or that A and B are both size_t (when available).
   - Heuristically recognize:
     - A is “current I/O length”: either a call expression containing the name “iov_iter_count” (ExprHasName(A, "iov_iter_count", C)) or a MemberExpr referring to “iter->count”.
     - B is an aligned length: call expression or macro text containing “round_up” or “roundup” or possibly “ALIGN”. You can use:
       - If CallExpr: get callee identifier and check name equals “round_up” or “roundup”.
       - Else: fallback to ExprHasName(B, "round_up", C) || ExprHasName(B, "roundup", C) || ExprHasName(B, "ALIGN", C).
   - If this structure doesn’t match, return.

5. Try trivial constant pruning (optional, to reduce FPs):
   - If both A and B evaluate to integers via EvaluateExprToInt and A >= B, then skip reporting.
   - Otherwise, proceed (we assume potential underflow exists).

6. Guard detection between definition of DiffExpr and the write to iter->count:
   - Look for a dominating guard that prevents underflow, in the same CompoundStmt between the statement defining DiffExpr (or ShrinkExpr) and S:
     - A guard like “if (shorten >= iter->count) shorten = 0;” or equivalent.
     - Or a condition that ensures B <= A, e.g., “if (round_up(...) > iov_iter_count(...)) { adjust; }”.
   - Implement a simple scan:
     - In the CompoundStmt body between the defining statement and S, search for an IfStmt.
     - For each IfStmt condition, use ExprHasName to look for:
       - Either: both names of Shrink variable and “count”, with a comparison operator “>=” or “>”, or
       - Both “round_up”/“roundup” and “iov_iter_count”/“count” with a comparison that implies B <= A (e.g., “round_up(...) > iov_iter_count(...)”).
     - Also check the guarded block for an assignment like “shorten = 0” or a branch that prevents subtracting too much (coarse heuristic: in the true branch, any assignment to shrink var to 0 or to a bounded value; you can do a simple ExprHasName on assignment target and RHS “0”).
   - If a suitable guard is found, return (do not warn).

7. Report:
   - Create a BugType once (e.g., “Underflow in I/O shrink”).
   - Generate a non-fatal error node and emit a PathSensitiveBugReport at S with a short message:
     - “Possible underflow: subtracting unsigned shorten may exceed iter->count”
     - Alternatively: “Potential underflow of iter->count when shrinking by aligned length”
   - Optionally add a note on the definition line of DiffExpr pointing out “shorten = A - round_up(...);” to improve diagnosability.

Helper utilities to implement/lean on:
- bool isIterCountMember(const Expr *E):
  - Return true if E is a MemberExpr named “count” whose base type stringifies to something containing “iov_iter”.
- bool looksLikeIovIterCount(const Expr *E, CheckerContext &C):
  - Return ExprHasName(E, "iov_iter_count", C) or E is isIterCountMember(E).
- bool looksLikeRoundUp(const Expr *E, CheckerContext &C):
  - If it’s a CallExpr with callee id “round_up” or “roundup”, return true.
  - Else fallback to ExprHasName(E, "round_up", C) || ExprHasName(E, "roundup", C) || ExprHasName(E, "ALIGN", C).
- const BinaryOperator* findLastAssignToVarBefore(const VarDecl *VD, const CompoundStmt *CS, const Stmt *Before):
  - Iterate CS->body() in order until Before; track last BinaryOperator with “=” or last DeclStmt initializing VD.

Notes:
- This checker is intentionally narrow to the kernel idiom:
  - It only triggers when subtracting an unsigned difference formed by the “current length minus aligned length” idiom involving iov_iter_count/iter->count and round_up/roundup/ALIGN.
  - It suppresses when a guard “shorten >= iter->count” (or equivalent) exists before the decrement, matching the upstream fix “if (shorten >= iter->count) shorten = 0;”.
- The implementation keeps things simple: no custom program state, no alias tracking, and only local-scope scans with available AST helpers.
- If desired, add a small whitelist to skip when the checker observes an immediate guard at the same line or on the previous statement to reduce false positives even further.
