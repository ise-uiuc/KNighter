Plan

1) Program state
- Do not introduce custom program state. Leverage the analyzer’s constraint manager to reason about the index range (inferSymbolMaxVal) and keep the checker simple and path-sensitive.

2) Primary callback: checkLocation
Goal: Detect potential or definite out-of-bounds array element access where the array has a known constant bound (e.g., TRANSFER_FUNC_POINTS) and the index can exceed that bound.

Implementation details:
- Trigger only on loads (IsLoad == true). We care about reading from LUT arrays like tf_pts.{red,green,blue}[i]. This avoids false positives on storing into other arrays.
- Extract the region:
  - Convert Loc to a MemRegion via Loc.getAs<loc::MemRegionVal>() and retrieve const MemRegion *R.
  - dyn_cast to const ElementRegion *ER; if it’s not an ElementRegion, return.
  - Get the index SVal: ER->getIndex(). If it’s not a nonloc::ConcreteInt or nonloc::SymbolVal (symbolic), return.
- Obtain the array bound:
  - Walk up ER->getSuperRegion() until you find a TypedValueRegion (FieldRegion/BaseRegion/etc.) and retrieve its QualType using getValueType(C.getASTContext()).
  - dyn_cast the QualType to ConstantArrayType; if not a constant array, return.
  - Get the array size: ConstantArrayType->getSize() (APInt) and convert to uint64_t (ArraySize).
- Decide if the access may be out-of-bounds:
  - If the index is a nonloc::ConcreteInt, compare to ArraySize. If Index >= ArraySize or Index < 0, report as a definite OOB.
  - If the index is symbolic (nonloc::SymbolVal):
    - Extract the SymbolRef; use inferSymbolMaxVal(IndexSym, C).
    - If maxVal is available and maxVal.uge(ArraySize), report a potential OOB (index can reach or exceed array bound).
    - If maxVal is unavailable (null), we cannot prove safety. Perform a few lightweight heuristics before reporting:
      - Try to see if this access is under a nearby explicit bound check in the AST. Use findSpecificTypeInParents to find the nearest IfStmt or loop condition (ForStmt/WhileStmt) from the Stmt argument S:
        - If an IfStmt or loop condition exists, and its condition source contains both the index variable’s textual name and the array bound name, suppress the report (likely guarded).
        - To get the index name: cast S to ArraySubscriptExpr and extract the index expression IE; use ExprHasName on the condition with the textual form of IE. To check bound symbol presence, also use ExprHasName with "TRANSFER_FUNC_POINTS" (or, more generally, the bound’s macro name if you can get it from the type’s size expr; if not, just check for the literal bound value).
      - If there is no nearby guard found, report a potential OOB (index not proven bounded by the array size).
- Reporting:
  - Create a BugType once (e.g., “Out-of-bounds LUT index”).
  - Generate a non-fatal error node via C.generateNonFatalErrorNode().
  - Build a PathSensitiveBugReport with message:
    - For definite issues: “Out-of-bounds array access: index is >= array size.”
    - For potential issues: “Possible out-of-bounds access: index may exceed array size; add ‘i < TRANSFER_FUNC_POINTS’ check.”
  - Add the source range of the index expression (ArraySubscriptExpr’s getIdx()) to highlight the exact code.
- Notes about the target pattern:
  - The buggy pattern terminates the loop based on j/hw_points while indexing with i. The constraint manager typically won’t infer a safe upper bound for i in such loops, causing maxVal to be unknown or too large, which will trigger the potential OOB report.
  - The last-point indexing (e.g., arr[start_index]) is handled the same way since ER->getIndex() will be that computed expression; if it’s not constrained against ArraySize, we warn.

3) Optional callback: checkBranchCondition (lightweight suppression)
Goal: Reduce false positives by recognizing explicit guard conditions that bound the index variable against the array bound.

Implementation details:
- When a branch condition is visited, if its condition is a binary comparison that clearly constrains the index variable (e.g., i < TRANSFER_FUNC_POINTS, i <= TRANSFER_FUNC_POINTS-1, TRANSFER_FUNC_POINTS > i, etc.), the constraint manager already learns this under the respective branch. Therefore, nothing is strictly necessary here.
- If you find the analyzer fails to propagate constraints consistently for macro constants, you can add an extra syntactic suppression flag on the ExplodedNode via ProgramPoint tags. However, prefer to rely on inferSymbolMaxVal as it reads the already-refined constraints.

4) Minor heuristics (still inside checkLocation)
- Prefer to report when the array base is clearly a LUT-like fixed-size buffer (the ConstantArrayType size is large and fixed). If needed, to closely match the patch case, you can additionally:
  - Check if the base expression text (use the Stmt S and its children) contains “tf_pts” and any of “red”, “green”, “blue” via ExprHasName, and raise the priority for such cases. This is optional; the core logic remains general.

5) No other callbacks required
- No need for checkPostCall, checkBind, or evalAssume. The constraint manager and the regional reasoning in checkLocation are sufficient for this pattern.

Summary of what this catches
- Accesses like output_tf->tf_pts.red[i] or .green[i] or .blue[i] when i is not provably constrained to be less than TRANSFER_FUNC_POINTS.
- Loop patterns where i grows by arithmetic and the loop exits based on a different counter (j/hw_points) will typically not refine i’s max value; the checker flags these as potential OOB.
- It also catches definite OOB when the index is concrete and >= bound, and “last point” patterns that compute start_index without proper bound checks.

Report message
- Keep it short and clear:
  - “Possible out-of-bounds access: index may exceed TRANSFER_FUNC_POINTS.”
  - For definite: “Out-of-bounds array access: index >= TRANSFER_FUNC_POINTS.”
