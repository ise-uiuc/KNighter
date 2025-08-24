1) Program state customization
- Not needed. This checker is a structural/AST pattern match with local reasoning. Avoid program state to keep it simple and robust.

2) Callback functions and step-by-step implementation

A) Main detection hook: checkLocation
Goal: Catch array indexing arr[i] where i is controlled by a for loop with an upper bound UB, and the array’s compile-time size is AS; warn if UB > AS (for <) or UB >= AS (for <=) and there is no guarding check before use.

Implementation steps:
1. Locate the ArraySubscriptExpr (ASE):
   - Given S (the Stmt of the current memory access), call findSpecificTypeInParents<ArraySubscriptExpr>(S, C). If null, return.
   - Let Base = ASE->getBase()->IgnoreParenImpCasts() and Idx = ASE->getIdx()->IgnoreParenImpCasts().

2. Extract the index variable:
   - If Idx is a DeclRefExpr to a VarDecl (IdxVar), keep it; otherwise, return (we only handle arr[i] where i is a variable).

3. Find the controlling ForStmt for IdxVar:
   - Use findSpecificTypeInParents<ForStmt>(ASE, C) to get the nearest for-loop; if none, return.
   - Verify whether this ForStmt’s induction variable is IdxVar. If not (e.g., it’s the inner j-loop), climb to the next parent for-loop and re-check. Repeat up to a reasonable depth (e.g., 3) or until no more ForStmt found.
   - To recognize the induction variable of a ForStmt:
     - Examine the Init of the ForStmt:
       - If it’s a DeclStmt with a single VarDecl, that VarDecl is the induction var.
       - Else if it’s a BinaryOperator like i = <expr>, the LHS DeclRefExpr refers to the induction VarDecl.
     - If the induction VarDecl equals IdxVar, we found the controlling loop.

4. Parse the loop bound (upper bound):
   - From the ForStmt condition Cond:
     - Expect a BinaryOperator BO with op in {<, <=}. If not, skip (we avoid !=, >, >=, etc., to reduce FPs).
     - Ensure one side of BO references IdxVar and the other side is the bound expression BoundExpr.
     - Normalize so that BoundExpr is the RHS describing the maximum domain limit (e.g., i < N or i <= N).
   - Evaluate BoundExpr to an integer UB:
     - Try EvaluateExprToInt(UB, BoundExpr, C). If it fails:
       - If BoundExpr is a symbolic value, try inferSymbolMaxVal(...) to get a max. If still fails, skip (we need a concrete bound to compare with array size).

5. Obtain the array compile-time size (AS):
   - We need to handle both DeclRefExpr and MemberExpr bases:
     - First try the provided helper getArraySizeFromExpr(ArraySize, Base). If it returns true, convert ArraySize (APInt) to APSInt.
     - Else, if Base is a MemberExpr:
       - Retrieve the FieldDecl FD = dyn_cast<FieldDecl>(MemberExpr->getMemberDecl()).
       - From FD->getType(), dyn_cast<ConstantArrayType> and getSize() to an APInt. Convert to an APSInt AS.
     - Else, if Base has type ConstantArrayType via desugaring, handle similarly. If we cannot get a ConstantArrayType and a constant size, skip.

6. Decide potential overflow from loop bound alone:
   - If BO is '<': accessing indices in [0, UB) requires UB <= AS to be safe. If UB > AS, then max index reachable is UB-1 >= AS, so potential OOB.
   - If BO is '<=': accessing indices in [0, UB] requires UB < AS to be safe. If UB >= AS, potential OOB.
   - If the condition indicates potential OOB, proceed to guard check; otherwise, return.

7. Guard detection (suppress if clearly guarded):
   - Look for a guarding if-condition in the ancestors that constrains IdxVar against the array bound AS:
     - Use findSpecificTypeInParents<IfStmt>(ASE, C) to get the nearest IfStmt ancestor; optionally repeat once or twice by calling findSpecificTypeInParents on that IfStmt to obtain higher IfStmt ancestors.
     - For each candidate IfStmt:
       - Extract its condition CondIf. If CondIf is a BinaryOperator comparing IdxVar to a constant BoundIf:
         - Evaluate BoundIf to integer BI via EvaluateExprToInt. If success and BI == AS:
           - If comparison is (IdxVar < AS) or (IdxVar <= AS - 1) or (IdxVar >= AS) or (IdxVar > AS - 1), consider it a bounds guard and suppress the warning.
       - If EvaluateExprToInt fails, as a last resort use ExprHasName(CondIf, IdxVar->getName(), C) and ExprHasName(CondIf, array base’s printed name, C) to conservatively detect potential guarding; if both appear and operators are typical (<, <=, >=, >), suppress to avoid FPs.
   - If no suitable guard is found, continue to report.

8. Report:
   - Create a non-fatal error node via C.generateNonFatalErrorNode().
   - Emit a PathSensitiveBugReport with a short message, e.g.:
     - "Index may exceed array bound: loop uses upper bound N, array size is M"
   - Optionally, include a note range on the for-condition and the array expression to aid debugging.

B) Optional: checkASTCodeBody (light, non-essential)
- Not required. All detection can be performed in checkLocation, which naturally provides parent access via CheckerContext and is triggered precisely when the array is accessed.

3) Important helper logic details

- Induction variable extraction from ForStmt:
  - For DeclStmt: single VarDecl initialized (e.g., for (int i = 0; ...)), VarDecl is the loop var.
  - For BinaryOperator: LHS is DeclRefExpr to the loop var (e.g., for (i = 0; i < N; i++)).

- Bound extraction and evaluation:
  - Only handle BO in {BO_LT, BO_LE}.
  - Recognize both forms: (IdxVar < Bound) and (Bound > IdxVar). Normalize to obtain BoundExpr.

- Array size extraction:
  - First try getArraySizeFromExpr for direct DeclRefExpr arrays.
  - Then handle MemberExpr: FieldDecl type should be ConstantArrayType; getSize().

- Macro awareness (optional):
  - Since macros are replaced by constants in the AST, EvaluateExprToInt should return a concrete integer for loop bounds.
  - If needed for diagnostics, you can use ExprHasName on the ForStmt condition to extract macro lexemes (e.g., "__DML_NUM_PLANES__") and on the array field’s declaration source to see if it mentions a different macro. This is optional and not necessary for correctness.

4) Heuristics to reduce false positives
- Only warn when both the loop bound and array size are successfully obtained as compile-time constants and the relation strictly indicates a possible OOB (as described in step A.6).
- Suppress when a nearby ancestor IfStmt compares the index variable against the same array-size constant (step A.7).
- Skip loops with non-standard conditions (e.g., not < or <=).
- Skip if index is not a simple variable (e.g., complex expressions).

5) Utility functions usage summary
- findSpecificTypeInParents<T>: to locate ArraySubscriptExpr, ForStmt, and IfStmt ancestors.
- EvaluateExprToInt: to obtain integer UB and BI from expressions (macro-expanded constants).
- ExprHasName: as a conservative fallback to recognize guarding conditions involving the same index variable and array symbol.
- getArraySizeFromExpr: used first for DeclRefExpr array bases.

6) Bug report message
- Keep it short and clear:
  - "Possible out-of-bounds: loop bound exceeds array size"
  - Include contextual info if available, e.g., "loop bound = N, array size = M".
