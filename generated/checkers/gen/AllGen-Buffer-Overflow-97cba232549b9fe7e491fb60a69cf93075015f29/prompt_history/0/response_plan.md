Plan to detect “for (i < N) with arr[i+1]” off-by-one OOB

1) Program state
- No custom program state is required. This checker is primarily syntactic/semantic and can be implemented with local AST inspection and constant evaluation.

2) Callback functions
- Use checkLocation (primary)
  - Rationale: Array element accesses (both loads and stores) trigger checkLocation with the ArraySubscriptExpr as Stmt*, which lets us analyze the index and its surrounding loop context precisely.

3) Detailed implementation steps

Step A: Trigger on array subscripts in checkLocation
- In checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C):
  - dyn_cast the Stmt S to const ArraySubscriptExpr *ASE. If not an ASE, return.
  - Extract the base expression BaseE = ASE->getBase()->IgnoreParenCasts().
  - Extract the index expression IdxE = ASE->getIdx()->IgnoreParenImpCasts().

Step B: Parse index “i + K”
- Attempt to match IdxE to the form “LoopVar +/- Const”:
  - If IdxE is a DeclRefExpr: not our target, return (we only care about i + 1 pattern).
  - If IdxE is a BinaryOperator BO with opcode BO_Add or BO_Sub:
    - Normalize so that one side is DeclRefExpr (VarDecl* LoopVarVD) and the other side is an integer constant (APSInt KVal).
      - Use EvaluateExprToInt to evaluate the constant operand.
      - If const evaluation fails, return.
      - For BO_Sub of form “i - C”, treat as K = -C.
      - We only report for K >= 1. If K <= 0, return.
  - If the above pattern fails, return.

Step C: Find the enclosing for-loop and extract loop condition
- Use findSpecificTypeInParents<ForStmt>(ASE, C) to find the closest for-loop F.
  - If not found, return.
- Analyze F->getCond():
  - After IgnoreParenImpCasts(), require a BinaryOperator CondBO.
  - Accept two canonical forms:
    - “i < BoundExpr” (CondBO->getOpcode() == BO_LT and LHS is the same LoopVarVD).
    - “BoundExpr > i” (CondBO->getOpcode() == BO_GT and RHS is the same LoopVarVD).
  - If neither matches with the same LoopVarVD, return.
  - Extract BoundExpr (the non-i side). Let BoundE be that expression (IgnoreParenImpCasts()).

Step D: Compute the array length of the subscripted base
- Implement a tiny helper inside the checker (used only here):
  - bool getConstArraySizeFromBase(const Expr *BaseE, llvm::APInt &ArrSize):
    - First try provided getArraySizeFromExpr(ArrSize, BaseE). If true, return true.
    - Else, if BaseE is a MemberExpr to a FieldDecl:
      - If FieldDecl->getType() is ConstantArrayType, retrieve size and return true.
    - Else, if BaseE is a UnaryOperator or ImplicitCast hiding a DeclRefExpr/MemberExpr, unwrap via IgnoreParenImpCasts() and retry.
    - Return false if not a constant array.
- If size cannot be determined, return.

Step E: Evaluate loop bound and compare to array size
- Evaluate BoundE to an integer with EvaluateExprToInt(BoundVal, BoundE, C).
  - If evaluation fails, return (we only handle constant/constexpr bounds).
- Compare ArrSize with BoundVal:
  - If ArrSize != BoundVal, return (to avoid FPs when loop bound is already N-1, or unrelated to this array).
  - Now we have: loop is “i < N” and array length is N, and index is “i + K” with K >= 1.

Step F: Skip if guarded inside the loop by an if-condition “i + K < Bound”
- Detect a guarding if that encloses the subscript but is inside the same for-loop:
  - Use findSpecificTypeInParents<IfStmt>(ASE, C) to get the nearest enclosing IfStmt IfS.
  - Ensure that IfS is lexically between ASE and the ForStmt found above (i.e., an ancestor of ASE and a descendant of F). If not, ignore.
  - Let Cond = IfS->getCond()->IgnoreParenImpCasts().
  - If Cond is a BinaryOperator with opcode BO_LT or BO_LE, check two patterns:
    - Left is a BinaryOperator BO_Add/BO_Sub with loop variable LoopVarVD and a constant K2 (EvaluateExprToInt). Right equals BoundE semantically (try evaluating both sides to int and compare values). If K2 >= K, consider guarded; skip reporting.
    - Or Left is the loop variable “i” and Right is “BoundExpr - K2” (where K2 >= K). Pattern: Right is BinaryOperator BO_Sub with RHS constant K2 and LHS BoundExpr equal to BoundE semantically. If satisfied, consider guarded; skip reporting.
  - If no such guarding condition is found, proceed to report.
  - You can use EvaluateExprToInt for constants and compare BoundE with the LHS of an eventual BO_Sub by evaluating both to integers. If integer evaluation of the Bound side fails, fall back to a textual check using ExprHasName to ensure the If condition references the same loop variable name and the bound’s source text; only skip if both are clearly present with a “<” comparison and a constant ≥ K.

Step G: Report the bug
- Create a BugType (category “Array bounds”, name “Possible out-of-bounds via i+1 in loop”).
- Use C.generateNonFatalErrorNode() to get an ExplodedNode. If null, return.
- Create a PathSensitiveBugReport with a short message:
  - “Loop iterates to last index while accessing arr[i+1] (off-by-one OOB).”
- Add a source range to highlight ASE->getSourceRange() or the index expression range.
- Emit the report.

4) Notes and heuristics to reduce false positives
- Only warn when all of the following hold simultaneously:
  - Index is syntactically “i +/- const”, with const >= 1.
  - For-loop condition is exactly “i < Bound” or “Bound > i”, using the same loop variable “i”.
  - Bound is a constant evaluable integer (EvaluateExprToInt succeeds).
  - Array size is a compile-time constant and equals Bound.
  - No guarding If-statement within the loop that ensures “i + const <= last valid index” (as described in Step F).
- Initially handle K == 1; allowing K >= 1 is fine with the same logic.

5) Utility functions used
- findSpecificTypeInParents (to find enclosing ForStmt and IfStmt).
- findSpecificTypeInChildren (optional inside Step F if you want to search “i+K” form inside the If condition).
- EvaluateExprToInt (to evaluate bounds and constants).
- getArraySizeFromExpr (used in the helper to obtain array length from DeclRefExpr bases).
- ExprHasName (fallback for textual guard detection when exact semantic matching fails).

6) Why this catches the target patch
- In the buggy code, the loop runs i < (MAX_PIPES * 2), and the access is links[i + 1], with links’ size equal to MAX_PIPES * 2. Our checker:
  - Recognizes index “i + 1” with K = 1.
  - Finds for-condition “i < (MAX_PIPES * 2)”, evaluates to BoundVal.
  - Retrieves links’ array length via MemberExpr -> FieldDecl -> ConstantArrayType.
  - Finds ArrSize == BoundVal, no guarding If, hence reports.
- The fixed code changes the loop bound to < (N - 1), so ArrSize != BoundVal; checker will not warn.
