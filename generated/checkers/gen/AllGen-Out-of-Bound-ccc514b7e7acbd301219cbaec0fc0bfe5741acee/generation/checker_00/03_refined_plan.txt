1) Program state
- No custom program state is needed. This checker is a structural/AST pattern check.

2) Callback functions
- Use only checkASTCodeBody. It lets us inspect each function body and search for the for-loop pattern.

3) Detailed steps

Step A. Scan function bodies for candidate for-loops (checkASTCodeBody)
- Iterate all statements in the function body and collect ForStmt nodes.
- For each ForStmt F, try to recognize a canonical “zero-to-bound” loop:
  - Init: either
    - DeclStmt with a single VarDecl V initialized to integer 0, or
    - BinaryOperator “i = 0” with LHS a DeclRefExpr to a VarDecl V.
  - Condition: a BinaryOperator using V and a bound expression, specifically
    - “i < BoundExpr” (primary target), optionally also support “i <= BoundExpr”.
  - Increment: do not strictly enforce form; it can be i++, ++i, i += 1, etc. We only need to know the loop index variable V.
- If the loop does not meet the above shape, skip it (keep the checker simple and precise).

Implementation notes:
- Extract the loop variable:
  - If init is DeclStmt: get the VarDecl* V and ensure its initializer evaluates to 0 with EvaluateExprToInt.
  - If init is BinaryOperator: ensure it is an assignment, LHS is DeclRefExpr to V, and RHS evaluates to 0.
- Extract and validate the condition:
  - Expect a BinaryOperator (BO_LT or optionally BO_LE).
  - Ensure the LHS is V (DeclRefExpr to the same VarDecl).
  - Record the BoundExpr (the RHS).
- Evaluate BoundExpr to an integer constant using EvaluateExprToInt. If it fails, skip this loop (to avoid false positives).
- Store:
  - VarDecl* LoopVar
  - APSInt BoundVal
  - A flag indicating whether the operator was “<” or “<=” (CompareKind).

Step B. Find arrays indexed by the loop variable inside the loop body
- Traverse the loop body subtree and collect all ArraySubscriptExpr (ASE) nodes.
- For each ASE:
  - Check that index expression is exactly the loop variable (DeclRefExpr to VarDecl V) after IgnoreImpCasts. If not, skip.
  - Determine the constant size of the array being indexed (the base of the subscript):
    - Case 1: Base is ultimately a DeclRefExpr to a VarDecl with array type.
      - Use the provided getArraySizeFromExpr(…).
    - Case 2: Base contains a MemberExpr (e.g., obj.field[i], ptr->field[i]).
      - Find the MemberExpr child with findSpecificTypeInChildren<MemberExpr>(ASE->getBase()).
      - Get the FieldDecl* from MemberExpr::getMemberDecl().
      - From FieldDecl->getType(), retrieve the ConstantArrayType. If present, obtain its size.
    - If the base is a pointer (no ConstantArrayType), or the array size cannot be determined, skip this ASE.
  - If we successfully obtain ArraySize (APInt -> uint64_t), compare it with the loop bound:
    - For “i < Bound”: if BoundVal > ArraySize, this array access may go out-of-bounds.
    - For “i <= Bound”: if BoundVal >= ArraySize, this array access may go out-of-bounds.
  - If the comparison indicates a possible overflow, record this ASE as a violation with:
    - The array name (from DeclRefExpr or MemberExpr pretty name).
    - The computed ArraySize and BoundVal.
    - The SourceRange of the ASE for reporting.

Notes to reduce noise (optional but simple):
- Only flag when index is exactly the loop variable (no offsets like i+1).
- Only flag when loop starts at 0 (already enforced).
- This matches the target pattern while keeping implementation simple and precise.

Step C. Report the bug (inside checkASTCodeBody)
- For each recorded violation, emit a BasicBugReport. Keep message short and clear, for example:
  - “Loop bound N exceeds array ‘X’ size M; X[i] may be out of bounds.”
- Attach the primary location to the ArraySubscriptExpr (ASE) and optionally highlight the loop condition’s RHS bound expression.
- Use a single BugType for the checker, e.g., “Parallel-array index overflow”.
- Prefer creating one report per array per loop (first occurrence) to avoid duplicates.

4) Helper routines to implement in the checker
- getCanonicalLoop(ForStmt*, VarDecl*& LoopVar, const Expr*& BoundExpr, bool& IsStrictLess):
  - Implements Step A (extract loop variable, ensure init is 0, and condition is i < Bound or i <= Bound).
- evalInt(const Expr*, APSInt& Out, CheckerContext or ASTContext):
  - Thin wrapper over EvaluateExprToInt to keep code uniform in this checker.
- indexIsLoopVar(const Expr* E, const VarDecl* V):
  - Return true if E->IgnoreImpCasts() is a DeclRefExpr to V.
- getArraySizeFromSubscriptBase(const Expr* Base, APInt& OutSize):
  - Tries utility getArraySizeFromExpr if Base leads to a DeclRefExpr.
  - Otherwise, find MemberExpr child, extract FieldDecl type, and if ConstantArrayType, return its size.
- getArrayName(const Expr* Base):
  - If DeclRefExpr: use DRE->getDecl()->getNameAsString().
  - If MemberExpr: use MemberExpr->getMemberDecl()->getNameAsString().
  - Fallback to ExprHasName(Base, …) if you want to enrich the message, but name is optional.

5) Why this catches the target bug
- The target bug is exactly: for (i = 0; i < SIZE_A; i++) { if (A[i] == key) return B[i]; }
- Our checker:
  - Detects i from 0 to Bound (SIZE_A);
  - Sees an ArraySubscriptExpr B[i] in the loop body;
  - Extracts B’s compile-time array size (SIZE_B);
  - If Bound > SIZE_B, it reports “Loop bound SIZE_A exceeds array ‘B’ size SIZE_B”, which matches the patch’s fix that introduces an extra bound check (break if i >= SIZE_B).

6) Chosen utilities and where used
- EvaluateExprToInt: evaluate bound expressions to integers.
- findSpecificTypeInChildren<T>: find MemberExpr inside ArraySubscriptExpr base for struct/field arrays.
- ExprHasName (optional): can be used to improve diagnostic text if needed.
- getArraySizeFromExpr: used directly for DeclRefExpr bases.

7) Callbacks summary
- checkASTCodeBody:
  - Walk ForStmt.
  - Extract loop variable and bound.
  - Walk loop body, find ArraySubscriptExpr with index = loop var.
  - Obtain array constant sizes and compare with bound.
  - Emit BasicBugReport on violations.

No other callbacks or program state needed.
