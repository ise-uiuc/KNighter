1) Program state
- No custom program state is necessary. This is an AST-level structural bug: a loop bound is derived from one array’s size but another, smaller array is indexed with the same induction variable. We can detect it without tracking symbolic execution.

2) Callbacks
- Use only checkASTCodeBody. We’ll perform a focused AST walk over loop statements in each function body and check their conditions and body for the target pattern.

3) Detailed plan for checkASTCodeBody
- Overview:
  - Traverse the body of the declaration D to find ForStmt (and optionally WhileStmt/DoStmt if you want to extend later).
  - For each ForStmt FS, extract:
    - The induction variable VarDecl* (i).
    - The loop upper bound UB expression and iteration direction (we’ll support i < UB and i <= UB).
  - Within the loop body, collect all array subscript expressions E[i] where the index expression refers to this induction variable i.
  - For each such array, determine its compile-time constant length if possible.
  - If the loop upper bound equals the size of one accessed array (call it A), but there exists another accessed array (B) with a smaller compile-time size, and both are indexed by i, report a warning on the use of B[i].

- Extracting loop shape (ForStmt):
  - Condition:
    - Expect a BinaryOperator (BO) with operator < or <=.
    - LHS must be a DeclRefExpr to the same loop variable i (VarDecl*).
    - RHS is UB expression.
    - Evaluate RHS to an integer with EvaluateExprToInt. If <, UBval = RHS; if <=, UBval = RHS + 1.
    - If evaluation fails, skip this loop to avoid false positives.
  - Induction variable:
    - From condition’s LHS DeclRefExpr get VarDecl* IVar.
  - Increment:
    - Prefer i++/++i/i+=1/i=i+1. If increment does not reference the same IVar or is not a positive step, skip to avoid complex cases. This narrowing is fine for the target pattern.

- Collecting array subscript uses indexed by i:
  - Recursively walk the loop body Stmt.
  - For each ArraySubscriptExpr ASE:
    - Check index expression: IgnoreParenImpCasts, it must be a DeclRefExpr to IVar.
    - Identify the array base (IgnoreParenImpCasts on ASE->getBase()):
      - If it is a MemberExpr to a FieldDecl FD, get FD->getType(); if ConstantArrayType, store:
        - A key identifying the array (FD pointer is enough).
        - Its constant length S = ConstantArrayType->getSize().
        - An example source location (the ASE) for later reporting.
      - Else if it is a DeclRefExpr to a VarDecl VD, and VD->getType() is ConstantArrayType, similarly record VD as the key with its size.
      - Otherwise (pointer, unknown, VLA, etc.), skip this array access since we can’t reliably get a size.
  - Deduplicate arrays by key (FieldDecl* or VarDecl*). Keep the smallest S we see for each key (they should be equal anyway).

- Decide if this loop is buggy:
  - We now have:
    - UBval: the loop’s upper bound (number of iterations if starting from 0 and using < or <=).
    - A set of arrays {Ai} with sizes Si that are indexed by i.
  - Heuristic to minimize false positives and match the target pattern:
    - Check if there exists an array A with size exactly equal to UBval (Si == UBval). This is the “big” or “bound” array that likely determines the loop bound.
    - Check if there exists another array B with a strictly smaller size (Sj < UBval).
    - If both exist, flag a bug.
  - Optional guard suppression (to avoid flagging already-fixed code):
    - Scan the loop body for a guard that prevents out-of-bounds on the smaller array:
      - Find an IfStmt whose condition compares i against Sj (operators >=, >, or == are typical), and whose then-branch contains a BreakStmt or ReturnStmt.
      - A simple approach:
        - For each Sj of a “small” array candidate, look for BinaryOperator on the If condition that references IVar and a constant equal to Sj, with operator >=, >, or == (consider commuted forms too).
        - Use findSpecificTypeInChildren<BreakStmt>(Then) or findSpecificTypeInChildren<ReturnStmt>(Then) to check for early exit.
      - If such a guard exists, suppress the warning for that pair.
    - This is a best-effort, not path-sensitive, but it suppresses the common fixed pattern “if (i >= SIZE_B) break;”.

- Reporting:
  - Create a single BugType for the checker, e.g., “Mismatched loop bound and array size”.
  - For the diagnostic location, use the ArraySubscriptExpr of the smaller array (B[i]) if available; otherwise the ForStmt condition.
  - Message should be short and clear:
    - “Loop bound uses size of one array but also indexes a smaller array with the same index; possible out-of-bounds.”
    - Optionally include array names (FieldDecl/VarDecl getNameAsString()) and sizes when known, e.g., “bound=8, array ‘DcfClocks’ size=7”.
  - Use std::make_unique<BasicBugReport> and emit once per loop (optionally per smaller array if multiple are present).

4) Helper logic details
- Getting constant array size:
  - For MemberExpr base ending at FieldDecl FD:
    - QualType T = FD->getType();
    - If const ConstantArrayType* CAT = dyn_cast<ConstantArrayType>(T.getTypePtr()), size = CAT->getSize().
  - For DeclRefExpr to VarDecl VD:
    - QualType T = VD->getType();
    - If ConstantArrayType, size = getSize().
  - Note: getArraySizeFromExpr utility works for DeclRefExpr but not MemberExpr; implement a small helper that handles MemberExpr as above and fallback to getArraySizeFromExpr(E) for DeclRefExpr.

- Matching the index variable:
  - For ArraySubscriptExpr::getIdx():
    - IgnoreParenImpCasts and check for DeclRefExpr.
    - Compare DRE->getDecl() pointer to the loop’s VarDecl* IVar.

- Evaluating the loop bound:
  - Use EvaluateExprToInt to get UB; if operator is <=, add 1 to the APInt as the effective iteration count.
  - Only proceed if evaluation succeeds.

- Optional: Lower bound and step:
  - To keep it simple and robust for the kernel pattern, assume loops start at 0 or small non-negative values.
  - You may check init is i=0 (BinaryOperator with i on LHS and integer literal 0 on RHS). If not found, you can still proceed; the critical comparison is UBval vs. array size.

5) Minimal use of other callbacks
- No need for checkPreCall/checkPostCall/checkBind/checkLocation/etc. The analysis is syntactic and confined within a loop’s AST.

6) Summary of detection rule
- If a for loop iterates i from 0 up to UB (i < UB or i <= UB), and inside the loop body there are at least two array subscripts A[i] and B[i] where A and B are distinct constant-sized arrays, and:
  - size(A) == UB, and size(B) < UB,
  - and there is no in-loop guard that breaks/returns when i reaches size(B),
  then report: “Loop bound uses size of one array but also indexes a smaller array with the same index; possible out-of-bounds.”
